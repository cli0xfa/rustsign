import { useCallback, useEffect } from 'react';
import { Toaster, toast } from 'sonner';
import { ThemeProvider, useTheme } from '@/contexts/ThemeContext';
import { completeStartup } from '@/lib/desktop';
import { LanguageProvider, useLanguage } from '@/contexts/LanguageContext';
import { WorkspaceProvider, useWorkspace } from '@/contexts/WorkspaceContext';
import { AppShell } from '@/components/layout/AppShell';
import { DropOverlay } from '@/components/layout/DropOverlay';
import { SignPage } from '@/components/pages/SignPage';
import { CertificatesPage } from '@/components/pages/CertificatesPage';
import { GenerateCertPage } from '@/components/pages/GenerateCertPage';
import { TsaPage } from '@/components/pages/TsaPage';
import { AuthModal } from '@/components/modals/AuthModal';
import { useDragDrop } from '@/hooks/useDragDrop';

function AppInner() {
  const { page, navigate, openFile, importPath, setImportPath, refreshCertificates } =
    useWorkspace();
  const { t } = useLanguage();
  const { resolved } = useTheme();
  useEffect(() => {
    // A hidden WebView may suspend rAF. Commit and force layout before the
    // native reveal; data fetching remains independent of this handoff.
    document.querySelector('.app-frame')?.getBoundingClientRect();
    const boot = document.getElementById('app-boot');
    if (boot) boot.dataset.dismissed = 'true';
    void completeStartup(resolved)
      .then(() => {
        document.documentElement.dataset.desktopReady = 'true';
      })
      .catch(() => toast.error(t('chrome.startupError'), { id: 'startup-error' }));
  }, [resolved, t]);
  const handlePe = useCallback(
    (path: string) => {
      if (openFile(path)) navigate('sign');
      else toast.info(t('wb.operationBusy'));
    },
    [openFile, navigate, t],
  );
  const handleCert = useCallback(
    (path: string) => {
      setImportPath(path);
      navigate('certs');
    },
    [setImportPath, navigate],
  );
  const unsupported = useCallback(() => {
    toast.error(t('messages.unsupportedFile'));
  }, [t]);
  const { isDragging } = useDragDrop({
    onPeFile: handlePe,
    onCertFile: handleCert,
    onUnsupported: unsupported,
  });
  return (
    <>
      <AppShell>
        {page === 'sign' && <SignPage />}
        {page === 'certs' && <CertificatesPage />}
        {page === 'gencert' && <GenerateCertPage />}
        {page === 'tsa' && <TsaPage />}
      </AppShell>
      <DropOverlay visible={isDragging} />
      {importPath && (
        <AuthModal
          ingress={{ mode: 'import', filePath: importPath, contextValue: importPath }}
          onClose={() => setImportPath(null)}
          onSuccess={() => {
            toast.success(t('wb.importSuccess'));
            void refreshCertificates().catch(() => {});
          }}
        />
      )}
    </>
  );
}

export default function App() {
  return (
    <ThemeProvider>
      <LanguageProvider>
        <WorkspaceProvider>
          <AppInner />
          <Toaster position="bottom-right" toastOptions={{ style: { fontSize: '14px' } }} />
        </WorkspaceProvider>
      </LanguageProvider>
    </ThemeProvider>
  );
}
