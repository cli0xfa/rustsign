export type Language = 'zh-CN' | 'en';
export type Theme = 'light' | 'dark';
export type SignModeType = 'app' | 'driver';
export type ResultTone = 'success' | 'error' | 'info';
export type PageKey = 'sign' | 'certs' | 'gencert' | 'tsa';
export type AuthModalMode = 'import' | 'exportPfx' | null;

export interface CertEntry {
  id: string;
  file_path: string;
  password?: string | null;
  subject: string;
  issuer: string;
  serial_number: string;
  not_before: string;
  not_after: string;
  signature_algorithm: string;
  thumbprint: string;
  not_before_secs?: number | null;
  not_after_secs?: number | null;
  has_private_key?: boolean | null;
  purposes?: string[] | null;
  is_ca?: boolean | null;
  can_issue?: boolean | null;
  file_readable?: boolean;
  read_error?: string | null;
}

export interface SignRules {
  default_sign_mode: string;
  default_digest_algo: string;
  default_timestamp?: string | null;
  auto_download_cross_cert: boolean;
  cross_cert_store_path: string;
}

export interface SignRequest {
  file_path: string;
  cert_id: string | null;
  cert_path: string | null;
  cert_password: string | null;
  sign_mode: SignModeType;
  digest_algorithm: string;
  timestamp_url: string | null;
  description: string | null;
  url: string | null;
  cross_cert_path: string | null;
  replace_signature: boolean;
}

export interface ActionResult {
  success: boolean;
  message: string;
}

export interface ExportBatchResult extends ActionResult {
  paths: string[];
}

export interface VerifyResult {
  valid: boolean;
  message: string;
  subject?: string | null;
  issuer?: string | null;
  digest_algorithm?: string | null;
  has_timestamp: boolean;
}

export interface CrossCertResult extends ActionResult {
  path?: string | null;
}

export interface FileFilter {
  name: string;
  extensions: string[];
}

export interface SignatureInfo {
  index: number;
  subject: string;
  digest_algorithm: string;
  has_timestamp: boolean;
  issuer?: string | null;
}

export interface TestCertOptions {
  root_cn: string;
  sign_cn: string;
  organization: string;
  country: string;
  validity_years: number;
  pfx_password: string;
  code_signing_eku: boolean;
  kernel_mode_eku: boolean;
}

export interface TestCertResult {
  success: boolean;
  message: string;
  root_pem: string;
  root_key_pem: string;
  sign_pem: string;
  sign_key_pem: string;
  sign_pfx_path: string | null;
  output_files: string[];
}

export interface CertGenOptions {
  root_cn: string;
  sign_cn: string;
  organization: string | null;
  country: string | null;
  validity_years: number;
  pfx_password: string;
  code_signing_eku: boolean;
  kernel_mode_eku: boolean;
  timestamp_eku: boolean;
  is_root_ca: boolean;
  issuer_cert_id: string | null;
}

export interface LocalTsaConfig {
  port: number;
  bind_address: string;
  cert_id: string | null;
  /** Unix timestamp (seconds). null = use current system time. */
  fixed_time_secs: number | null;
  digest_algorithm: string;
  /** Display name for this TSA (appears in the timestamp token). */
  tsa_name: string | null;
}

export interface LocalTsaStatus {
  running: boolean;
  port: number;
  bind_address: string;
  url: string;
}
