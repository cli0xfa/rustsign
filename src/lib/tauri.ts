import type {
  ActionResult,
  CertEntry,
  CertGenOptions,
  CrossCertResult,
  ExportBatchResult,
  FileFilter,
  LocalTsaConfig,
  LocalTsaStatus,
  SignatureInfo,
  SignRequest,
  SignRules,
  TestCertResult,
  VerifyResult,
} from '@/types';
import { CommandError, normalizeError } from './errors';

function rawInvoke<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  if (!window.__TAURI__?.core?.invoke) {
    return Promise.reject(new CommandError('unavailable', 'Tauri API is unavailable.'));
  }
  return window.__TAURI__.core.invoke<T>(command, args ?? {}).catch((error: unknown) => {
    throw normalizeError(error);
  });
}

export async function signPeFile(request: SignRequest): Promise<ActionResult> {
  return rawInvoke<ActionResult>('sign_pe_file', { request });
}

export async function removePeSignature(filePath: string): Promise<ActionResult> {
  return rawInvoke<ActionResult>('remove_pe_signature', { filePath });
}

export async function verifyPeSignature(filePath: string): Promise<VerifyResult> {
  return rawInvoke<VerifyResult>('verify_pe_signature', { filePath });
}

export async function listPeSignatures(filePath: string): Promise<SignatureInfo[]> {
  return rawInvoke<SignatureInfo[]>('list_pe_signatures', { filePath });
}

export async function removePeSignatureAt(filePath: string, index: number): Promise<ActionResult> {
  return rawInvoke<ActionResult>('remove_pe_signature_at', { filePath, index });
}

export async function reorderPeSignatures(
  filePath: string,
  order: number[],
): Promise<ActionResult> {
  return rawInvoke<ActionResult>('reorder_pe_signatures', { filePath, order });
}

export async function addTimestamp(
  filePath: string,
  tsaUrl: string,
  digestAlgorithm?: string,
): Promise<ActionResult> {
  return rawInvoke<ActionResult>('add_timestamp', {
    filePath,
    tsaUrl,
    digestAlgorithm: digestAlgorithm ?? null,
  });
}

export async function removeTimestamp(filePath: string): Promise<ActionResult> {
  return rawInvoke<ActionResult>('remove_timestamp', { filePath });
}

export async function generateTestCert(
  options: CertGenOptions,
  outputDir?: string,
): Promise<TestCertResult> {
  return rawInvoke<TestCertResult>('generate_test_cert', {
    options,
    outputDir: outputDir ?? null,
  });
}

export async function listCertificates(): Promise<CertEntry[]> {
  return rawInvoke<CertEntry[]>('list_certificates');
}

export async function importCertificate(
  filePath: string,
  password?: string,
): Promise<ActionResult> {
  return rawInvoke<ActionResult>('import_certificate', {
    filePath,
    password: password ?? null,
  });
}

export async function deleteCertificate(id: string): Promise<void> {
  return rawInvoke<void>('delete_certificate', { id });
}

export async function exportCertificates(
  ids: string[],
  format: string,
  outputDir: string,
  password?: string,
): Promise<ExportBatchResult> {
  return rawInvoke<ExportBatchResult>('export_certificates_command', {
    ids,
    format,
    outputDir,
    password: password ?? null,
  });
}

export async function downloadCrossCert(): Promise<CrossCertResult> {
  return rawInvoke<CrossCertResult>('download_cross_cert');
}

export async function loadRules(): Promise<SignRules> {
  return rawInvoke<SignRules>('load_rules');
}

export async function openFileDialog(
  title: string,
  filters: FileFilter[],
  multiple = false,
): Promise<string | null> {
  return rawInvoke<string | null>('open_file_dialog', {
    request: { title, multiple, filters },
  });
}

export async function openDirectoryDialog(title: string): Promise<string | null> {
  return rawInvoke<string | null>('open_directory_dialog', { title });
}

export async function startLocalTsa(config: LocalTsaConfig): Promise<LocalTsaStatus> {
  return rawInvoke<LocalTsaStatus>('start_tsa_server', { config });
}

export async function stopLocalTsa(): Promise<LocalTsaStatus> {
  return rawInvoke<LocalTsaStatus>('stop_tsa_server');
}

export async function getLocalTsaStatus(): Promise<LocalTsaStatus> {
  return rawInvoke<LocalTsaStatus>('get_tsa_server_status');
}

export async function loadLocalTsaConfig(): Promise<LocalTsaConfig> {
  return rawInvoke<LocalTsaConfig>('load_local_tsa_config_command');
}
