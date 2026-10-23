import type { CertEntry, LocalTsaConfig, LocalTsaStatus, SignatureInfo } from '@/types';
export const certificate: CertEntry = {
  id: 'test-identity',
  subject: 'Acme Software Signing',
  issuer: 'Acme Test Root CA',
  serial_number: 'AB12',
  file_path: 'C:\\fixtures\\identity.pfx',
  thumbprint: '1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234',
  signature_algorithm: '1.2.840.113549.1.1.11',
  not_before: '2025-01-01T00:00:00Z',
  not_after: '2030-01-01T00:00:00Z',
  not_before_secs: 1735689600,
  not_after_secs: 1893456000,
  has_private_key: true,
  purposes: ['1.3.6.1.5.5.7.3.3'],
  is_ca: false,
  can_issue: false,
  file_readable: true,
};
export const tsaConfig: LocalTsaConfig = {
  port: 18080,
  bind_address: '127.0.0.1',
  cert_id: null,
  fixed_time_secs: null,
  digest_algorithm: 'sha256',
  tsa_name: null,
};
export const tsaStatus: LocalTsaStatus = {
  running: false,
  port: 18080,
  bind_address: '127.0.0.1',
  url: 'http://127.0.0.1:18080',
};
export const signature: SignatureInfo = {
  index: 0,
  subject: 'Acme Software Signing',
  digest_algorithm: 'SHA-256',
  has_timestamp: false,
};
export function installBridge(
  overrides: Record<string, (args: Record<string, unknown>) => unknown | Promise<unknown>> = {},
  certificates = [certificate],
) {
  const calls: { command: string; args: Record<string, unknown> }[] = [];
  const items = [...certificates];
  let signatures: SignatureInfo[] = [];
  window.__TAURI__ = {
    core: {
      invoke: async <T>(command: string, args: Record<string, unknown> = {}): Promise<T> => {
        calls.push({ command, args });
        if (overrides[command]) return (await overrides[command](args)) as T;
        const result = (() => {
          switch (command) {
            case 'load_rules':
              return { default_digest_algo: 'sha256', default_timestamp: '' };
            case 'load_local_tsa_config_command':
              return { ...tsaConfig };
            case 'get_tsa_server_status':
              return { ...tsaStatus };
            case 'list_certificates':
              return [...items];
            case 'list_pe_signatures':
              return [...signatures];
            case 'open_file_dialog':
              return (
                args.request as { filters: { extensions: string[] }[] }
              ).filters[0].extensions.includes('exe')
                ? 'C:\\build\\client.exe'
                : certificate.file_path;
            case 'open_directory_dialog':
              return 'C:\\export';
            case 'import_certificate':
              items.push({ ...certificate, id: `imported-${items.length}` });
              return { success: true, message: 'Imported' };
            case 'sign_pe_file':
              signatures = [signature];
              return { success: true, message: 'Signed' };
            case 'verify_pe_signature':
              return {
                valid: true,
                has_timestamp: false,
                subject: certificate.subject,
                issuer: certificate.issuer,
                digest_algorithm: 'SHA-256',
                message: 'Digest matches',
              };
            case 'remove_pe_signature':
            case 'remove_pe_signature_at':
              signatures = [];
              return { success: true, message: 'Removed' };
            case 'export_certificates_command':
              return { success: true, message: 'Exported', paths: ['C:\\export\\identity.pem'] };
            default:
              return { success: true, message: 'Completed' };
          }
        })();
        return result as T;
      },
    },
  };
  return { calls, items };
}
