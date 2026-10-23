import type { Page } from '@playwright/test';
import { certificate, signature, tsaConfig, tsaStatus } from '../../src/test/fixtures';

export async function bridge(
  page: Page,
  options: {
    empty?: boolean;
    signed?: boolean;
    language?: string;
    theme?: string;
    failCertificates?: boolean;
    failSign?: boolean;
    slowSign?: boolean;
    longPath?: boolean;
    runningTsa?: boolean;
    busyClose?: boolean;
    failStartup?: boolean;
  } = {},
) {
  await page.addInitScript(
    ({ certificate, signature, tsaConfig, tsaStatus, options }) => {
      localStorage.setItem('rustsign-language', options.language ?? 'zh-CN');
      localStorage.setItem('rustsign-theme', options.theme ?? 'dark');
      const items = options.empty
        ? []
        : [
            certificate,
            {
              ...certificate,
              id: 'expired-identity',
              subject: 'Acme Legacy Signing',
              not_after: '2020-01-01T00:00:00Z',
              not_before_secs: 0,
              not_after_secs: 1577836800,
            },
            {
              ...certificate,
              id: 'public-identity',
              subject: 'Acme Public Certificate',
              has_private_key: false,
            },
          ];
      let signatures = options.signed
        ? [
            signature,
            { ...signature, index: 1, subject: 'Acme Legacy Signing', has_timestamp: true },
          ]
        : [];
      let status = { ...tsaStatus, running: options.runningTsa === true };
      let certFailure = options.failCertificates === true;
      let signFailure = options.failSign === true;
      const calls: { command: string; args: Record<string, unknown> }[] = [];
      Object.assign(window, { __bridgeCalls: calls });
      let maximized = false;
      const resizeListeners = new Set<() => void>();
      window.__TAURI__ = {
        window: {
          getCurrentWindow: () => ({
            onDragDropEvent: async () => () => {},
            isMaximized: async () => maximized,
            isFocused: async () => true,
            setTitle: async (title) => {
              calls.push({ command: 'window:set-title', args: { title } });
            },
            minimize: async () => {
              calls.push({ command: 'window:minimize', args: {} });
            },
            toggleMaximize: async () => {
              maximized = !maximized;
              calls.push({ command: 'window:toggle-maximize', args: {} });
              resizeListeners.forEach((listener) => listener());
            },
            maximize: async () => {
              maximized = true;
              resizeListeners.forEach((listener) => listener());
            },
            unmaximize: async () => {
              maximized = false;
              resizeListeners.forEach((listener) => listener());
            },
            onResized: async (listener) => {
              resizeListeners.add(listener);
              return () => {
                resizeListeners.delete(listener);
              };
            },
            onScaleChanged: async () => () => {},
          }),
        },
        core: {
          invoke: async <T>(command: string, args: Record<string, unknown> = {}): Promise<T> => {
            calls.push({ command, args });
            let result: unknown;
            switch (command) {
              case 'complete_startup':
                if (options.failStartup) throw new Error('Native reveal failed');
                result = null;
                break;
              case 'sync_window_chrome':
                result = null;
                break;
              case 'request_app_close':
                result = options.busyClose
                  ? 'busy'
                  : status.running && !args.confirmTsaStop
                    ? 'confirm-tsa'
                    : 'closing';
                break;
              case 'load_rules':
                result = { default_digest_algo: 'sha256', default_timestamp: '' };
                break;
              case 'load_local_tsa_config_command':
                result = tsaConfig;
                break;
              case 'get_tsa_server_status':
                result = status;
                break;
              case 'list_certificates':
                if (certFailure) {
                  certFailure = false;
                  throw {
                    category: 'io',
                    message: 'The certificate database is temporarily unavailable.',
                  };
                }
                result = items;
                break;
              case 'open_file_dialog': {
                const request = args.request as { filters: { extensions: string[] }[] };
                result = request.filters[0].extensions.includes('exe')
                  ? options.longPath
                    ? 'C:\\build\\release\\very-long-directory-name-for-layout-validation\\windows\\amd64\\client.exe'
                    : 'C:\\build\\client.exe'
                  : certificate.file_path;
                break;
              }
              case 'open_directory_dialog':
                result = 'C:\\export';
                break;
              case 'list_pe_signatures':
                result = signatures;
                break;
              case 'import_certificate':
                items.push({ ...certificate, id: `imported-${items.length}` });
                result = { success: true, message: 'Imported certificate' };
                break;
              case 'sign_pe_file':
                if (signFailure) {
                  signFailure = false;
                  throw {
                    category: 'signing',
                    message: 'Temporary signing failure; configuration was retained.',
                  };
                }
                if (options.slowSign) await new Promise((resolve) => setTimeout(resolve, 700));
                signatures = [signature];
                result = { success: true, message: 'Signature written to C:\\build\\client.exe' };
                break;
              case 'verify_pe_signature':
                result = {
                  valid: true,
                  subject: certificate.subject,
                  issuer: certificate.issuer,
                  digest_algorithm: 'SHA-256',
                  has_timestamp: true,
                  message: 'CMS signature valid; Authenticode digest matches',
                };
                break;
              case 'remove_pe_signature':
                signatures = [];
                result = { success: true, message: 'All signatures removed' };
                break;
              case 'remove_pe_signature_at':
                signatures = signatures.filter((sig) => sig.index !== args.index);
                result = { success: true, message: 'Signature removed' };
                break;
              case 'reorder_pe_signatures': {
                const order = args.order as number[];
                signatures = order.map((index, position) => ({
                  ...signatures.find((sig) => sig.index === index)!,
                  index: position,
                }));
                result = { success: true, message: 'Signature order updated' };
                break;
              }
              case 'delete_certificate': {
                const index = items.findIndex((cert) => cert.id === args.id);
                if (index >= 0) items.splice(index, 1);
                result = null;
                break;
              }
              case 'export_certificates_command':
                result = {
                  success: true,
                  message: 'Exported certificates',
                  paths: ['C:\\export\\identity.pem'],
                };
                break;
              case 'generate_test_cert':
                result = {
                  success: true,
                  message: 'Generated test certificates',
                  root_pem: '',
                  root_key_pem: '',
                  sign_pem: '',
                  sign_key_pem: '',
                  sign_pfx_path: 'C:\\export\\generated.pfx',
                  output_files: ['C:\\export\\generated.pem', 'C:\\export\\generated.pfx'],
                };
                break;
              case 'start_tsa_server': {
                const config = args.config as typeof tsaConfig;
                status = {
                  running: true,
                  port: config.port,
                  bind_address: config.bind_address,
                  url: `http://${config.bind_address}:${config.port}`,
                };
                result = status;
                break;
              }
              case 'stop_tsa_server':
                status = { ...status, running: false };
                result = status;
                break;
              default:
                result = { success: true, message: 'Operation completed' };
            }
            return structuredClone(result) as T;
          },
        },
      };
    },
    { certificate, signature, tsaConfig, tsaStatus, options },
  );
}
