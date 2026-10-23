import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}

const PE_EXTENSIONS = new Set(['exe', 'dll', 'sys', 'ocx', 'cab']);
const CERT_EXTENSIONS = new Set(['pfx', 'p12', 'pem', 'crt', 'cer']);

export type SignMode = 'app' | 'driver';
export type DropFileKind = 'pe' | 'cert' | 'unsupported';

export function baseName(filePath: string): string {
  const parts = filePath.split(/[/\\]/);
  return parts[parts.length - 1] || filePath;
}

export function getFileExtension(filePath: string | null | undefined): string {
  return (
    String(filePath ?? '')
      .split('.')
      .pop()
      ?.toLowerCase() ?? ''
  );
}

export function inferSignMode(filePath: string): SignMode {
  return filePath.toLowerCase().endsWith('.sys') ? 'driver' : 'app';
}

export function classifyDroppedFile(filePath: string | null | undefined): DropFileKind {
  const ext = getFileExtension(filePath);
  if (PE_EXTENSIONS.has(ext)) return 'pe';
  if (CERT_EXTENSIONS.has(ext)) return 'cert';
  return 'unsupported';
}

export function formatDigestLabel(algorithm: string | null | undefined): string {
  switch (String(algorithm ?? 'sha256').toLowerCase()) {
    case 'sha1':
      return 'SHA-1';
    case 'sha384':
      return 'SHA-384';
    case 'sha512':
      return 'SHA-512';
    default:
      return 'SHA-256';
  }
}

const CERT_ALGO_MAP: Record<string, string> = {
  '1.2.840.113549.1.1.1': 'RSA',
  '1.2.840.113549.1.1.4': 'MD5+RSA',
  '1.2.840.113549.1.1.5': 'SHA-1+RSA',
  '1.2.840.113549.1.1.11': 'SHA-256+RSA',
  '1.2.840.113549.1.1.12': 'SHA-384+RSA',
  '1.2.840.113549.1.1.13': 'SHA-512+RSA',
  '1.2.840.10045.2.1': 'ECDSA',
  '1.2.840.10045.4.1': 'ECDSA+SHA-1',
  '1.2.840.10045.4.3.1': 'ECDSA+SHA-256',
  '1.2.840.10045.4.3.2': 'ECDSA+SHA-384',
  '1.2.840.10045.4.3.3': 'ECDSA+SHA-512',
};

export function formatCertAlgo(oid: string | null | undefined): string {
  if (!oid) return '--';
  return CERT_ALGO_MAP[oid] ?? oid;
}
