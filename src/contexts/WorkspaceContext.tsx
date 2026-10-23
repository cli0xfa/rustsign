import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useLayoutEffect,
  useReducer,
  useRef,
  useState,
} from 'react';
import * as tauri from '@/lib/tauri';
import { errorKey, normalizeError } from '@/lib/errors';
import { initialWorkspace, workspaceReducer, unixToLocalInput } from '@/lib/workspace';
import type { TaskResult, WorkspaceState, WorkspaceAction } from '@/lib/workspace';
import type { CertEntry, LocalTsaStatus, PageKey } from '@/types';
import { TIMESTAMP_SERVICES } from '@/lib/constants';

interface CertificateState {
  items: CertEntry[];
  status: 'loading' | 'ready' | 'error';
  error: unknown;
}
interface TsaRuntime {
  status: 'loading' | 'ready' | 'error';
  value: LocalTsaStatus | null;
  error: unknown;
  busy: boolean;
  result: TaskResult | null;
}
interface WorkspaceContextValue {
  state: WorkspaceState;
  dispatch: React.Dispatch<WorkspaceAction>;
  page: PageKey;
  navigate: (page: PageKey) => void;
  certificates: CertificateState;
  refreshCertificates: () => Promise<CertEntry[]>;
  openFile: (path: string) => boolean;
  choosePeFile: () => Promise<void>;
  chooseCertificate: () => Promise<void>;
  refreshSignatures: () => Promise<void>;
  runFileOperation: (
    name: string,
    action: () => Promise<TaskResult>,
    revision?: number,
  ) => Promise<void>;
  generateCertificate: () => Promise<void>;
  tsaRuntime: TsaRuntime;
  refreshTsa: () => Promise<void>;
  runTsa: (action: () => Promise<LocalTsaStatus>, successKey: string) => Promise<void>;
  importPath: string | null;
  setImportPath: (path: string | null) => void;
}
const WorkspaceContext = createContext<WorkspaceContextValue | null>(null);

export function WorkspaceProvider({ children }: { children: React.ReactNode }) {
  const [state, dispatch] = useReducer(workspaceReducer, initialWorkspace);
  const [page, navigate] = useState<PageKey>('sign');
  const [certificates, setCertificates] = useState<CertificateState>({
    items: [],
    status: 'loading',
    error: null,
  });
  const [tsaRuntime, setTsaRuntime] = useState<TsaRuntime>({
    status: 'loading',
    value: null,
    error: null,
    busy: false,
    result: null,
  });
  const [importPath, setImportPath] = useState<string | null>(null);
  const stateRef = useRef(state);
  const revisionRef = useRef(0);
  const certRequest = useRef(0);
  const tsaRequest = useRef(0);
  const signatureRequest = useRef(0);
  const fileLock = useRef(false);
  const generateLock = useRef(false);
  const tsaLock = useRef(false);
  const dialogLock = useRef(false);
  const mounted = useRef(false);
  useLayoutEffect(() => {
    stateRef.current = state;
  }, [state]);

  const refreshCertificates = useCallback(async () => {
    const request = ++certRequest.current;
    setCertificates((current) => ({ ...current, status: 'loading', error: null }));
    try {
      const items = await tauri.listCertificates();
      if (mounted.current && request === certRequest.current) {
        setCertificates({ items, status: 'ready', error: null });
        const selected = stateRef.current.sign.certId;
        if (selected && !items.some((cert) => cert.id === selected))
          dispatch({ type: 'sign', patch: { certId: '' } });
      }
      return items;
    } catch (error) {
      if (mounted.current && request === certRequest.current)
        setCertificates((current) => ({ ...current, status: 'error', error }));
      throw error;
    }
  }, []);

  const loadSignatures = useCallback(async (path: string, revision: number) => {
    const request = ++signatureRequest.current;
    dispatch({ type: 'signatures', revision, loading: true });
    try {
      const signatures = await tauri.listPeSignatures(path);
      if (mounted.current && request === signatureRequest.current)
        dispatch({ type: 'signatures', revision, signatures });
    } catch (error) {
      if (mounted.current && request === signatureRequest.current)
        dispatch({ type: 'signatures', revision, error: normalizeError(error).message });
    }
  }, []);

  const openFile = useCallback(
    (path: string) => {
      if (fileLock.current) return false;
      const revision = ++revisionRef.current;
      dispatch({ type: 'file', path, revision });
      void loadSignatures(path, revision);
      return true;
    },
    [loadSignatures],
  );

  const refreshSignatures = useCallback(async () => {
    const { path, revision } = stateRef.current.file;
    if (path) await loadSignatures(path, revision);
  }, [loadSignatures]);

  const choosePeFile = useCallback(async () => {
    if (fileLock.current || dialogLock.current) return;
    dialogLock.current = true;
    try {
      const path = await tauri.openFileDialog(
        document.documentElement.lang === 'en' ? 'Choose PE file' : '选择 PE 文件',
        [{ name: 'PE', extensions: ['exe', 'dll', 'sys', 'ocx', 'cab'] }],
      );
      if (path && openFile(path)) navigate('sign');
    } finally {
      dialogLock.current = false;
    }
  }, [openFile]);

  const chooseCertificate = useCallback(async () => {
    if (dialogLock.current) return;
    dialogLock.current = true;
    try {
      const path = await tauri.openFileDialog(
        document.documentElement.lang === 'en' ? 'Import certificate' : '导入证书',
        [{ name: 'Certificate', extensions: ['pfx', 'p12', 'pem', 'crt', 'cer'] }],
      );
      if (path) {
        setImportPath(path);
        navigate('certs');
      }
    } finally {
      dialogLock.current = false;
    }
  }, []);

  const runFileOperation = useCallback(
    async (name: string, action: () => Promise<TaskResult>, revision?: number) => {
      const file = stateRef.current.file;
      if (fileLock.current || !file.path || (revision !== undefined && revision !== file.revision))
        return;
      fileLock.current = true;
      dispatch({ type: 'operation', operation: name });
      try {
        const result = await action();
        if (mounted.current) dispatch({ type: 'result', revision: file.revision, result });
        if (name !== 'verify') await loadSignatures(file.path, file.revision);
      } catch (error) {
        if (mounted.current)
          dispatch({
            type: 'result',
            revision: file.revision,
            result: {
              tone: 'error',
              title: errorKey(error),
              details: normalizeError(error).message,
            },
          });
      } finally {
        fileLock.current = false;
        if (mounted.current) dispatch({ type: 'operation', operation: null });
      }
    },
    [loadSignatures],
  );

  const generateCertificate = useCallback(async () => {
    if (generateLock.current) return;
    generateLock.current = true;
    const draft = stateRef.current.generate;
    dispatch({
      type: 'generation',
      patch: { busy: true, files: null, result: null, password: draft.options.pfx_password },
    });
    try {
      const files = await tauri.generateTestCert(draft.options, draft.outputDir || undefined);
      if (!files.success) throw new Error(files.message);
      if (mounted.current)
        dispatch({
          type: 'generation',
          patch: {
            files,
            result: { tone: 'success', title: 'wb.generated', details: files.message },
          },
        });
    } catch (error) {
      if (mounted.current)
        dispatch({
          type: 'generation',
          patch: {
            result: {
              tone: 'error',
              title: errorKey(error),
              details: normalizeError(error).message,
            },
          },
        });
    } finally {
      generateLock.current = false;
      if (mounted.current) dispatch({ type: 'generation', patch: { busy: false } });
    }
  }, []);

  const refreshTsa = useCallback(async () => {
    if (tsaLock.current) return;
    const request = ++tsaRequest.current;
    try {
      const value = await tauri.getLocalTsaStatus();
      if (mounted.current && request === tsaRequest.current)
        setTsaRuntime((current) => ({
          ...current,
          status: 'ready',
          value,
          error: null,
          busy: false,
        }));
    } catch (error) {
      if (mounted.current && request === tsaRequest.current)
        setTsaRuntime((current) => ({ ...current, status: 'error', error }));
    }
  }, []);

  const runTsa = useCallback(async (action: () => Promise<LocalTsaStatus>, successKey: string) => {
    if (tsaLock.current) return;
    tsaLock.current = true;
    ++tsaRequest.current;
    setTsaRuntime((current) => ({ ...current, busy: true, error: null }));
    try {
      const value = await action();
      if (mounted.current)
        setTsaRuntime({
          status: 'ready',
          value,
          error: null,
          busy: false,
          result: { tone: 'success', title: successKey },
        });
    } catch (error) {
      if (mounted.current)
        setTsaRuntime((current) => ({
          ...current,
          busy: false,
          error,
          result: { tone: 'error', title: errorKey(error), details: normalizeError(error).message },
        }));
      throw error;
    } finally {
      tsaLock.current = false;
    }
  }, []);

  useEffect(() => {
    mounted.current = true;
    void refreshCertificates().catch(() => {});
    void refreshTsa();
    void tauri
      .loadRules()
      .then((rules) => {
        if (!mounted.current) return;
        const service = rules.default_timestamp ?? '';
        dispatch({
          type: 'sign',
          defaults: true,
          patch: {
            digest: rules.default_digest_algo || 'sha256',
            timestampService: TIMESTAMP_SERVICES.some((item) => item.value === service)
              ? service
              : 'custom',
            customTimestampUrl: service,
          },
        });
      })
      .catch(() => {});
    void tauri
      .loadLocalTsaConfig()
      .then((config) => {
        if (mounted.current)
          dispatch({
            type: 'tsa',
            defaults: true,
            patch: {
              config,
              useFixedTime: config.fixed_time_secs != null,
              fixedDatetime: config.fixed_time_secs ? unixToLocalInput(config.fixed_time_secs) : '',
            },
          });
      })
      .catch(() => {});
    const interval = setInterval(() => {
      void refreshTsa();
    }, 5000);
    return () => {
      mounted.current = false;
      clearInterval(interval);
    };
  }, [refreshCertificates, refreshTsa]);

  return (
    <WorkspaceContext.Provider
      value={{
        state,
        dispatch,
        page,
        navigate,
        certificates,
        refreshCertificates,
        openFile,
        choosePeFile,
        chooseCertificate,
        refreshSignatures,
        runFileOperation,
        generateCertificate,
        tsaRuntime,
        refreshTsa,
        runTsa,
        importPath,
        setImportPath,
      }}
    >
      {children}
    </WorkspaceContext.Provider>
  );
}

// Context and its hook intentionally share one module.
// eslint-disable-next-line react-refresh/only-export-components
export function useWorkspace() {
  const context = useContext(WorkspaceContext);
  if (!context) throw new Error('WorkspaceProvider is missing');
  return context;
}
