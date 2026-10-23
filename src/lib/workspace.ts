import type {
  CertGenOptions,
  LocalTsaConfig,
  SignatureInfo,
  TestCertResult,
  VerifyResult,
} from '@/types';

export type FileTab = 'sign' | 'verify' | 'manage';
export interface TaskResult {
  tone: 'success' | 'error' | 'info';
  title: string;
  details?: string;
  verification?: VerifyResult;
}
export interface SignDraft {
  certId: string;
  digest: string;
  timestampService: string;
  customTimestampUrl: string;
  mode: 'replace' | 'append';
  description: string;
  url: string;
  crossCert: string;
}
export interface GenerateDraft {
  options: CertGenOptions;
  outputDir: string;
}
export interface TsaDraft {
  config: LocalTsaConfig;
  useFixedTime: boolean;
  fixedDatetime: string;
}
export interface WorkspaceState {
  tab: FileTab;
  file: {
    path: string;
    revision: number;
    signatures: SignatureInfo[];
    status: 'idle' | 'loading' | 'ready' | 'error';
    error: string | null;
  };
  sign: SignDraft;
  signDirty: boolean;
  operation: string | null;
  result: TaskResult | null;
  generate: GenerateDraft;
  generation: {
    busy: boolean;
    result: TaskResult | null;
    files: TestCertResult | null;
    password: string | null;
  };
  tsa: TsaDraft;
  tsaDirty: boolean;
}
export const initialWorkspace: WorkspaceState = {
  tab: 'sign',
  file: { path: '', revision: 0, signatures: [], status: 'idle', error: null },
  sign: {
    certId: '',
    digest: 'sha256',
    timestampService: '',
    customTimestampUrl: '',
    mode: 'replace',
    description: '',
    url: '',
    crossCert: '',
  },
  signDirty: false,
  operation: null,
  result: null,
  generate: {
    options: {
      root_cn: 'RustSign Test Root CA',
      sign_cn: 'RustSign Test Code Signing',
      organization: null,
      country: null,
      validity_years: 5,
      pfx_password: 'test123',
      code_signing_eku: true,
      kernel_mode_eku: true,
      timestamp_eku: false,
      is_root_ca: true,
      issuer_cert_id: null,
    },
    outputDir: '',
  },
  generation: { busy: false, result: null, files: null, password: null },
  tsa: {
    config: {
      port: 18080,
      bind_address: '127.0.0.1',
      cert_id: null,
      fixed_time_secs: null,
      digest_algorithm: 'sha256',
      tsa_name: null,
    },
    useFixedTime: false,
    fixedDatetime: '',
  },
  tsaDirty: false,
};
export type WorkspaceAction =
  | { type: 'tab'; tab: FileTab }
  | { type: 'file'; path: string; revision: number }
  | {
      type: 'signatures';
      revision: number;
      signatures?: SignatureInfo[];
      error?: string;
      loading?: boolean;
    }
  | { type: 'sign'; patch: Partial<SignDraft>; defaults?: boolean }
  | { type: 'operation'; operation: string | null }
  | { type: 'result'; result: TaskResult | null; revision: number }
  | { type: 'generate'; patch: Partial<GenerateDraft> }
  | { type: 'generation'; patch: Partial<WorkspaceState['generation']> }
  | { type: 'tsa'; patch: Partial<TsaDraft>; defaults?: boolean };

export function workspaceReducer(state: WorkspaceState, action: WorkspaceAction): WorkspaceState {
  switch (action.type) {
    case 'tab':
      return { ...state, tab: action.tab };
    case 'file':
      if (state.operation) return state;
      return {
        ...state,
        file: {
          path: action.path,
          revision: action.revision,
          signatures: [],
          status: 'loading',
          error: null,
        },
        result: null,
      };
    case 'signatures':
      if (action.revision !== state.file.revision) return state;
      return {
        ...state,
        file: {
          ...state.file,
          status: action.loading ? 'loading' : action.error ? 'error' : 'ready',
          error: action.error ?? null,
          signatures: action.signatures ?? state.file.signatures,
        },
      };
    case 'sign':
      if (action.defaults && state.signDirty) return state;
      return {
        ...state,
        sign: { ...state.sign, ...action.patch },
        signDirty: !action.defaults || state.signDirty,
      };
    case 'operation':
      return { ...state, operation: action.operation };
    case 'result':
      return action.revision === state.file.revision ? { ...state, result: action.result } : state;
    case 'generate':
      return { ...state, generate: { ...state.generate, ...action.patch } };
    case 'generation':
      return { ...state, generation: { ...state.generation, ...action.patch } };
    case 'tsa':
      if (action.defaults && state.tsaDirty) return state;
      return {
        ...state,
        tsa: { ...state.tsa, ...action.patch },
        tsaDirty: !action.defaults || state.tsaDirty,
      };
  }
}

export function unixToLocalInput(seconds: number): string {
  const date = new Date(seconds * 1000);
  const pad = (value: number) => String(value).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}
export function localInputToUnix(value: string): number | null {
  const ms = new Date(value).getTime();
  return Number.isFinite(ms) && ms > 0 ? Math.floor(ms / 1000) : null;
}
