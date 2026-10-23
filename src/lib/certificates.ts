import type { CertEntry } from '@/types';
export type CertificateValidity =
  | 'valid'
  | 'expiring'
  | 'expired'
  | 'notYetValid'
  | 'unknown'
  | 'unreadable';
export function certificateValidity(cert: CertEntry, now = Date.now() / 1000): CertificateValidity {
  if (cert.file_readable === false) return 'unreadable';
  if (cert.not_before_secs == null || cert.not_after_secs == null) return 'unknown';
  if (cert.not_before_secs > now) return 'notYetValid';
  if (cert.not_after_secs < now) return 'expired';
  return cert.not_after_secs - now <= 30 * 86400 ? 'expiring' : 'valid';
}
export function canUsePrivateKey(cert: CertEntry | undefined): boolean {
  return !!cert && cert.has_private_key !== false && cert.file_readable !== false;
}
export function certificatePurposeKeys(cert: CertEntry): string[] {
  if (cert.purposes == null) return ['wb.unknown'];
  const keys: string[] = [];
  if (cert.is_ca) keys.push('wb.ca');
  const names: Record<string, string> = {
    '1.3.6.1.5.5.7.3.3': 'wb.codeSigning',
    '1.3.6.1.4.1.311.61.1.1': 'wb.kernelSigning',
    '1.3.6.1.5.5.7.3.8': 'wb.timestampSigning',
  };
  keys.push(...cert.purposes.map((oid) => names[oid] ?? oid));
  return keys.length ? keys : ['wb.unrestricted'];
}
export function isHttpUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return ['http:', 'https:'].includes(url.protocol) && !!url.hostname;
  } catch {
    return false;
  }
}
