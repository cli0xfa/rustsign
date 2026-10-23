export const STORAGE_KEYS = {
  theme: 'rustsign-theme',
  language: 'rustsign-language',
} as const;

export const PE_EXTENSIONS = new Set(['exe', 'dll', 'sys', 'ocx', 'cab']);
export const CERT_EXTENSIONS = new Set(['pfx', 'p12', 'pem', 'crt', 'cer']);

export const TIMESTAMP_SERVICES = [
  { value: '', label: 'sign.timestampNone' },
  { value: 'http://timestamp.digicert.com', label: 'DigiCert' },
  { value: 'http://timestamp.sectigo.com', label: 'Sectigo' },
  { value: 'http://tsa.starfieldtech.com', label: 'Starfield' },
  { value: 'custom', label: 'sign.timestampCustom' },
] as const;

export const DIGEST_ALGORITHMS = [
  { value: 'sha256', label: 'SHA-256' },
  { value: 'sha1', label: 'SHA-1' },
  { value: 'sha384', label: 'SHA-384' },
  { value: 'sha512', label: 'SHA-512' },
] as const;

export const EXPORT_FORMATS = [
  { value: 'pem', label: 'PEM' },
  { value: 'pfx', label: 'PFX' },
  { value: 'pvk_spc', label: 'PVK + SPC' },
] as const;

export const GEN_CERT_VALIDITY = [
  { value: '1', label: '1 year' },
  { value: '3', label: '3 years' },
  { value: '5', label: '5 years' },
  { value: '10', label: '10 years' },
] as const;
