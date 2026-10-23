use crate::CodeSignError;
use goblin::pe::PE;
use std::path::Path;

#[derive(Debug, Clone, Copy)]
struct CertificateTableInfo {
    entry_offset: usize,
    cert_offset: usize,
    cert_size: usize,
}

/// A single WIN_CERTIFICATE entry from the certificate table.
#[derive(Debug, Clone)]
pub struct SignatureEntry {
    pub data: Vec<u8>,
}

/// Read all WIN_CERTIFICATE entries from a PE file's certificate table.
/// WIN_CERTIFICATE entries are stored consecutively. Each entry's dwLength
/// is already rounded up to a multiple of 8 for all entries except the first
/// (PE spec only requires 8-byte alignment for entries after the first).
pub fn read_all_signatures(data: &[u8]) -> Result<Vec<SignatureEntry>, CodeSignError> {
    let info = certificate_table_info(data)?;
    if info.cert_size == 0 {
        return Ok(Vec::new());
    }
    if info.cert_offset + info.cert_size > data.len() {
        return Err(CodeSignError::Pe(
            "Certificate table out of bounds".to_string(),
        ));
    }

    let table = &data[info.cert_offset..info.cert_offset + info.cert_size];
    let mut entries = Vec::new();
    let mut offset = 0usize;
    let mut is_first = true;

    while offset + 8 <= table.len() {
        let dw_length = u32::from_le_bytes([
            table[offset],
            table[offset + 1],
            table[offset + 2],
            table[offset + 3],
        ]) as usize;

        if dw_length < 8 || offset + dw_length > table.len() {
            break;
        }

        // Only entries after the first must be 8-byte aligned per PE spec
        if !is_first && !dw_length.is_multiple_of(8) {
            break;
        }

        let w_revision = u16::from_le_bytes([table[offset + 4], table[offset + 5]]);
        let w_cert_type = u16::from_le_bytes([table[offset + 6], table[offset + 7]]);

        if w_revision == 0x0200 && w_cert_type == 0x0002 {
            let cert_data = strip_padding(&table[offset + 8..offset + dw_length]);
            entries.push(SignatureEntry {
                data: cert_data.to_vec(),
            });
        }

        offset += dw_length;
        is_first = false;
    }

    Ok(entries)
}

/// Trim trailing zero padding from certificate data, returning only the
/// actual DER bytes.
fn strip_padding(data: &[u8]) -> &[u8] {
    match der_object_total_length(data) {
        Some(len) if len <= data.len() => &data[..len],
        _ => data,
    }
}

/// Compute the total length of a DER-encoded TLV object from its header.
fn der_object_total_length(data: &[u8]) -> Option<usize> {
    if data.len() < 2 {
        return None;
    }

    let length_byte = data[1];
    if length_byte & 0x80 == 0 {
        return Some(2 + length_byte as usize);
    }

    let length_bytes = (length_byte & 0x7f) as usize;
    if length_bytes == 0
        || length_bytes > std::mem::size_of::<usize>()
        || data.len() < 2 + length_bytes
    {
        return None;
    }

    let mut value_length = 0usize;
    for byte in &data[2..2 + length_bytes] {
        value_length = value_length.checked_mul(256)?.checked_add(*byte as usize)?;
    }

    2usize.checked_add(length_bytes)?.checked_add(value_length)
}

/// Write signatures to a PE file.
/// If `replace` is true, the existing certificate table is removed first.
/// If false, the new signature is appended to existing entries.
pub fn write_signature(
    original_data: &[u8],
    signature: &[u8],
    output_path: &Path,
    replace: bool,
) -> Result<(), CodeSignError> {
    let mut entries: Vec<Vec<u8>> = if !replace {
        read_all_signatures(original_data)?
            .iter()
            .map(|e| e.data.clone())
            .collect()
    } else {
        Vec::new()
    };
    entries.push(signature.to_vec());
    write_signatures_entries(original_data, &entries, output_path)
}

/// Write multiple signature DER entries to a PE file, replacing any existing
/// certificate table. Each entry is written as a separate WIN_CERTIFICATE.
pub fn write_signatures_entries(
    original_data: &[u8],
    entries: &[Vec<u8>],
    output_path: &Path,
) -> Result<(), CodeSignError> {
    let info = certificate_table_info(original_data)?;
    let mut new_data = original_data.to_vec();

    // Remove old certificate table
    if info.cert_size > 0 {
        let cert_end = info
            .cert_offset
            .checked_add(info.cert_size)
            .ok_or_else(|| CodeSignError::Pe("Certificate table size overflow".to_string()))?;
        if cert_end > new_data.len() {
            return Err(CodeSignError::Pe(
                "Certificate table out of bounds".to_string(),
            ));
        }
        new_data.drain(info.cert_offset..cert_end);
    }

    clear_certificate_table_entry(&mut new_data, info.entry_offset)?;

    if entries.is_empty() {
        std::fs::write(output_path, &new_data)?;
        return Ok(());
    }

    // For a first-ever signature, align the table start to 8 bytes so that
    // all subsequent appended signatures can reuse the same aligned offset.
    // For overwrites we preserve the original offset (Authenticode digest
    // correctness depends on the cert table location staying stable).
    let needs_alignment = info.cert_size == 0;
    if needs_alignment {
        let pad = (8 - (new_data.len() % 8)) % 8;
        new_data.resize(new_data.len() + pad, 0);
    }

    let signature_offset = new_data.len();
    for entry_data in entries {
        let entry = build_win_cert(entry_data);
        new_data.extend_from_slice(&entry);
    }

    let new_cert_size = (new_data.len() - signature_offset) as u32;
    update_certificate_table(
        &mut new_data,
        info.entry_offset,
        signature_offset as u32,
        new_cert_size,
    )?;

    std::fs::write(output_path, new_data)?;
    Ok(())
}

/// Remove a specific signature by index. Returns the new PE bytes.
/// Handles both separate WIN_CERTIFICATE entries and nested signatures
/// within a single entry.
pub fn remove_signature_at(data: &[u8], index: usize) -> Result<Vec<u8>, CodeSignError> {
    let info = certificate_table_info(data)?;
    let entries = read_all_signatures(data)?;

    if entries.is_empty() {
        return Err(CodeSignError::Pe("No signatures to remove".to_string()));
    }

    // Nested case: single WIN_CERTIFICATE entry may contain multiple signatures.
    if entries.len() == 1 {
        let chain = crate::verify::collect_nested_cms_chain(&entries[0].data)?;
        if index < chain.len() {
            return remove_from_nested_chain(data, &chain, index, &info);
        }
        // fall through to out-of-range error below
    }

    if index >= entries.len() {
        return Err(CodeSignError::Pe(format!(
            "Signature index {} out of range (0..{})",
            index,
            entries.len()
        )));
    }

    let mut entries = entries;
    entries.remove(index);
    rebuild_certificate_table(data, &entries, &info)
}

/// Reorder signatures. `order` is a permutation of 0..signature_count.
/// Handles both separate WIN_CERTIFICATE entries and nested signatures.
pub fn reorder_signatures(data: &[u8], order: &[usize]) -> Result<Vec<u8>, CodeSignError> {
    let info = certificate_table_info(data)?;
    let entries = read_all_signatures(data)?;

    // Nested case: single WIN_CERTIFICATE entry may contain multiple signatures.
    if entries.len() == 1 && order.len() > 1 {
        let chain = crate::verify::collect_nested_cms_chain(&entries[0].data)?;
        if order.len() != chain.len() {
            return Err(CodeSignError::Pe(format!(
                "Order length {} does not match nested signature count {}",
                order.len(),
                chain.len()
            )));
        }
        return reorder_nested_chain(data, &chain, order, &info);
    }

    if order.len() != entries.len() {
        return Err(CodeSignError::Pe(format!(
            "Order length {} does not match signature count {}",
            order.len(),
            entries.len()
        )));
    }

    let mut seen = vec![false; entries.len()];
    let mut reordered = Vec::with_capacity(entries.len());
    for &idx in order {
        if idx >= entries.len() || seen[idx] {
            return Err(CodeSignError::Pe("Invalid order permutation".to_string()));
        }
        seen[idx] = true;
        reordered.push(entries[idx].clone());
    }

    rebuild_certificate_table(data, &reordered, &info)
}

/// Remove a signature from a nested CMS chain at the given index.
/// `chain` is ordered outermost → innermost, matching the indices from
/// `list_signatures`.
fn remove_from_nested_chain(
    data: &[u8],
    chain: &[Vec<u8>],
    index: usize,
    info: &CertificateTableInfo,
) -> Result<Vec<u8>, CodeSignError> {
    let remaining: Vec<Vec<u8>> = chain
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != index)
        .map(|(_, der)| der.clone())
        .collect();

    if remaining.is_empty() {
        return rebuild_certificate_table(data, &[], info);
    }

    let new_outer = crate::verify::rebuild_nested_cms_chain(&remaining)?;
    let new_entry = SignatureEntry { data: new_outer };
    rebuild_certificate_table(data, &[new_entry], info)
}

/// Reorder signatures within a nested CMS chain.
/// `chain` is ordered outermost → innermost.
fn reorder_nested_chain(
    data: &[u8],
    chain: &[Vec<u8>],
    order: &[usize],
    info: &CertificateTableInfo,
) -> Result<Vec<u8>, CodeSignError> {
    let mut seen = vec![false; chain.len()];
    let mut reordered: Vec<Vec<u8>> = Vec::with_capacity(chain.len());
    for &idx in order {
        if idx >= chain.len() || seen[idx] {
            return Err(CodeSignError::Pe("Invalid order permutation".to_string()));
        }
        seen[idx] = true;
        reordered.push(chain[idx].clone());
    }

    let new_outer = crate::verify::rebuild_nested_cms_chain(&reordered)?;
    let new_entry = SignatureEntry { data: new_outer };
    rebuild_certificate_table(data, &[new_entry], info)
}

/// Build a WIN_CERTIFICATE structure with dwLength padded to a multiple of 8.
fn build_win_cert(data: &[u8]) -> Vec<u8> {
    let raw_len = 8 + data.len();
    let padded_len = raw_len.div_ceil(8) * 8;
    let mut entry = Vec::with_capacity(padded_len);
    entry.extend_from_slice(&(padded_len as u32).to_le_bytes());
    entry.extend_from_slice(&0x0200u16.to_le_bytes());
    entry.extend_from_slice(&0x0002u16.to_le_bytes());
    entry.extend_from_slice(data);
    entry.resize(padded_len, 0);
    entry
}

fn rebuild_certificate_table(
    data: &[u8],
    entries: &[SignatureEntry],
    info: &CertificateTableInfo,
) -> Result<Vec<u8>, CodeSignError> {
    let mut new_data = data.to_vec();

    // Remove old certificate table
    if info.cert_size > 0 {
        let cert_end = info
            .cert_offset
            .checked_add(info.cert_size)
            .ok_or_else(|| CodeSignError::Pe("Certificate table size overflow".to_string()))?;
        if cert_end > new_data.len() {
            return Err(CodeSignError::Pe(
                "Certificate table out of bounds".to_string(),
            ));
        }
        new_data.drain(info.cert_offset..cert_end);
    }

    clear_certificate_table_entry(&mut new_data, info.entry_offset)?;

    if entries.is_empty() {
        return Ok(new_data);
    }

    let signature_offset = new_data.len();

    for entry in entries {
        let cert = build_win_cert(&entry.data);
        new_data.extend_from_slice(&cert);
    }

    let new_cert_size = (new_data.len() - signature_offset) as u32;
    update_certificate_table(
        &mut new_data,
        info.entry_offset,
        signature_offset as u32,
        new_cert_size,
    )?;

    Ok(new_data)
}

pub fn remove_signature(file_path: &Path) -> Result<bool, CodeSignError> {
    let mut data = std::fs::read(file_path)?;
    let info = certificate_table_info(&data)?;

    if info.cert_size == 0 {
        return Ok(false);
    }

    let cert_end = info
        .cert_offset
        .checked_add(info.cert_size)
        .ok_or_else(|| CodeSignError::Pe("Certificate table size overflow".to_string()))?;
    if cert_end > data.len() {
        return Err(CodeSignError::Pe(
            "Certificate table out of bounds".to_string(),
        ));
    }

    data.drain(info.cert_offset..cert_end);
    clear_certificate_table_entry(&mut data, info.entry_offset)?;
    std::fs::write(file_path, data)?;
    Ok(true)
}

fn certificate_table_info(data: &[u8]) -> Result<CertificateTableInfo, CodeSignError> {
    let pe =
        PE::parse(data).map_err(|e| CodeSignError::Pe(format!("Failed to parse PE: {e:?}")))?;

    let optional_header = pe
        .header
        .optional_header
        .ok_or_else(|| CodeSignError::Pe("No optional header found".to_string()))?;

    let entry_offset = certificate_table_entry_offset(&pe, data.len())?;
    let cert_dir = optional_header.data_directories.get_certificate_table();

    Ok(CertificateTableInfo {
        entry_offset,
        cert_offset: cert_dir
            .map(|directory| directory.virtual_address as usize)
            .unwrap_or(0),
        cert_size: cert_dir
            .map(|directory| directory.size as usize)
            .unwrap_or(0),
    })
}

fn certificate_table_entry_offset(pe: &PE, data_len: usize) -> Result<usize, CodeSignError> {
    let is_pe32_plus = pe.header.coff_header.machine == goblin::pe::header::COFF_MACHINE_X86_64;
    let optional_header_offset = pe.header.dos_header.pe_pointer as usize
        + 4
        + std::mem::size_of::<goblin::pe::header::CoffHeader>();

    let num_dirs_offset = if is_pe32_plus {
        optional_header_offset + 0x6c
    } else {
        optional_header_offset + 0x5c
    };

    let entry_offset = num_dirs_offset + 4 + 4 * 8;
    if entry_offset + 8 > data_len {
        return Err(CodeSignError::Pe(
            "Certificate table directory entry out of bounds".to_string(),
        ));
    }

    Ok(entry_offset)
}

fn clear_certificate_table_entry(
    data: &mut [u8],
    entry_offset: usize,
) -> Result<(), CodeSignError> {
    if entry_offset + 8 > data.len() {
        return Err(CodeSignError::Pe(
            "Certificate table directory entry out of bounds".to_string(),
        ));
    }

    data[entry_offset..entry_offset + 8].fill(0);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_and_read_multiple_signatures() {
        // Find a test PE file
        let test_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("demo")
            .join("bin");
        let src = test_dir.join("test.sys");
        if !src.exists() {
            eprintln!("Skipping: test.sys not found");
            return;
        }

        let tmp = std::env::temp_dir().join(format!(
            "multi-sig-test-{}.sys",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::copy(&src, &tmp).unwrap();

        let sig1 = vec![0x30, 0x03, 0x02, 0x01, 0x01]; // minimal DER
        let sig2 = vec![0x30, 0x03, 0x02, 0x01, 0x02];

        // Write first signature (replace = true)
        write_signature(&std::fs::read(&tmp).unwrap(), &sig1, &tmp, true).unwrap();

        // Write second signature (replace = false = append)
        write_signature(&std::fs::read(&tmp).unwrap(), &sig2, &tmp, false).unwrap();

        // Read back
        let data = std::fs::read(&tmp).unwrap();
        let entries = read_all_signatures(&data).unwrap();
        assert_eq!(
            entries.len(),
            2,
            "Expected 2 signatures, got {}",
            entries.len()
        );

        let _ = std::fs::remove_file(&tmp);
    }
}

fn update_certificate_table(
    data: &mut [u8],
    entry_offset: usize,
    offset: u32,
    size: u32,
) -> Result<(), CodeSignError> {
    if entry_offset + 8 > data.len() {
        return Err(CodeSignError::Pe(
            "Certificate table directory entry out of bounds".to_string(),
        ));
    }

    data[entry_offset..entry_offset + 4].copy_from_slice(&offset.to_le_bytes());
    data[entry_offset + 4..entry_offset + 8].copy_from_slice(&size.to_le_bytes());
    Ok(())
}
