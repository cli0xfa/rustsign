import { Header } from './Header';
import { useCallback, useEffect, useState } from 'react';
import { Circle, ShieldCheck } from 'lucide-react';
import { toast } from 'sonner';
import { useWorkspace } from '@/contexts/WorkspaceContext';
import { useLanguage } from '@/contexts/LanguageContext';
import { TitleBar } from './TitleBar';
import type { ShellAction } from './TitleBar';
import {
  desktopWindow,
  desktopVersion,
  listenDesktop,
  requestAppClose,
  windowAction,
} from '@/lib/desktop';
import type { CaptionAction, CloseState } from '@/lib/desktop';
import { normalizeError } from '@/lib/errors';
import { baseName } from '@/lib/utils';
import {
  Dialog,
  DialogHeader,
  DialogBody,
  DialogClose,
  ConfirmDialog,
} from '@/components/ui/Dialog';
import type { Confirmation } from '@/components/ui/Dialog';
import type { PageKey } from '@/types';

function workspaceLabel(page: PageKey, t: (key: string) => string) {
  return t(
    page === 'sign'
      ? 'wb.workspace'
      : page === 'certs'
        ? 'wb.library'
        : page === 'gencert'
          ? 'wb.generate'
          : 'tabs.tsa',
  );
}

function modalIsOpen() {
  return !!document.querySelector(
    '[role="dialog"][data-state="open"], [role="alertdialog"][data-state="open"]',
  );
}

export function AppShell({ children }: { children: React.ReactNode }) {
  const { state, page, navigate, choosePeFile, chooseCertificate, tsaRuntime, certificates } =
    useWorkspace();
  const { t } = useLanguage();
  const [maximized, setMaximized] = useState(false);
  const [focused, setFocused] = useState(true);
  const [captionState, setCaptionState] = useState('');
  const [windowMenuOpen, setWindowMenuOpen] = useState(false);
  const [blocked, setBlocked] = useState(false);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [help, setHelp] = useState<'shortcuts' | 'about' | null>(null);
  const [version, setVersion] = useState('');
  const [activity, setActivity] = useState(0);
  const [confirmation, setConfirmation] = useState<Confirmation | null>(null);
  const reportError = useCallback((error: unknown) => {
    toast.error(normalizeError(error).message, { id: 'desktop-error' });
  }, []);
  const handleCloseState = useCallback(
    (result: CloseState | undefined) => {
      if (result === 'busy') toast.info(t('chrome.busyClose'), { id: 'busy-close' });
      if (result === 'confirm-tsa')
        setConfirmation({
          title: t('chrome.closeTsaTitle'),
          description: t('chrome.closeTsaHint'),
          target: tsaRuntime.value?.url ?? 'Local TSA',
          onConfirm: () => {
            void requestAppClose(true)
              .then((next) => {
                if (next === 'busy') toast.info(t('chrome.busyClose'));
              })
              .catch(reportError);
          },
        });
    },
    [reportError, t, tsaRuntime.value?.url],
  );
  const close = useCallback(() => {
    if (state.operation || state.generation.busy) {
      toast.info(t('chrome.busyClose'), { id: 'busy-close' });
      return;
    }
    void requestAppClose().then(handleCloseState).catch(reportError);
  }, [handleCloseState, reportError, state.operation, state.generation.busy, t]);
  const navigateTo = useCallback(
    (target: PageKey) => {
      navigate(target);
      setDrawerOpen(false);
    },
    [navigate],
  );
  const action = useCallback(
    (command: ShellAction) => {
      switch (command) {
        case 'open':
          if (!state.operation) void choosePeFile().catch(reportError);
          break;
        case 'import':
          void chooseCertificate().catch(reportError);
          break;
        case 'exit':
          close();
          break;
        case 'about':
          setHelp('about');
          void desktopVersion().then(setVersion).catch(reportError);
          break;
        case 'shortcuts':
          setHelp('shortcuts');
          break;
        default:
          navigateTo(command);
      }
    },
    [chooseCertificate, choosePeFile, close, navigateTo, reportError, state.operation],
  );
  const title = `${workspaceLabel(page, t)}${state.file.path ? ` · ${baseName(state.file.path)}` : ''}`;

  useEffect(() => {
    document.title = `${title} — RustSign`;
    void desktopWindow()?.setTitle?.(document.title).catch(reportError);
  }, [title, reportError]);

  useEffect(() => {
    const observer = new MutationObserver(() => {
      setBlocked(modalIsOpen() || !!document.querySelector('[role="menu"]'));
    });
    observer.observe(document.body, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ['data-state'],
    });
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    let alive = true;
    const off: (() => void)[] = [];
    const register = (promise: Promise<() => void> | undefined) => {
      void promise
        ?.then((dispose) => {
          if (alive) off.push(dispose);
          else dispose();
        })
        .catch(reportError);
    };
    const current = desktopWindow();
    const readMaximized = () => {
      void current
        ?.isMaximized?.()
        .then((value) => {
          if (alive) setMaximized(value);
        })
        .catch(reportError);
    };
    readMaximized();
    void current
      ?.isFocused?.()
      .then((value) => {
        if (alive) setFocused(value);
      })
      .catch(reportError);
    register(current?.onResized?.(readMaximized));
    register(
      current?.onFocusChanged?.(({ payload }) => {
        if (alive) setFocused(payload);
      }),
    );
    register(listenDesktop<CloseState>('desktop://close-state', handleCloseState));
    register(listenDesktop<string>('desktop://close-error', reportError));
    register(listenDesktop<number>('desktop://activity', setActivity));
    register(
      listenDesktop('desktop://window-menu', () => {
        if (!modalIsOpen()) setWindowMenuOpen(true);
      }),
    );
    register(
      listenDesktop<CaptionAction>('desktop://caption', (event) => {
        if (event === 'click') void windowAction('toggle').catch(reportError);
        else setCaptionState(event === 'leave' || event === 'up' ? '' : event);
      }),
    );
    return () => {
      alive = false;
      off.forEach((dispose) => dispose());
    };
  }, [handleCloseState, reportError]);

  useEffect(() => {
    const keydown = (event: KeyboardEvent) => {
      if (event.defaultPrevented || event.repeat || modalIsOpen()) return;
      let command: ShellAction | undefined;
      if (event.ctrlKey && !event.altKey && !event.metaKey) {
        if (event.key.toLowerCase() === 'o' && !event.shiftKey) command = 'open';
        if (event.key.toLowerCase() === 'i' && event.shiftKey) command = 'import';
        if (!event.shiftKey)
          command ??= ({ '1': 'sign', '2': 'certs', '3': 'tsa' } as Record<string, ShellAction>)[
            event.key
          ];
      }
      if (event.key === 'F1') command = 'shortcuts';
      if (event.altKey && event.key === ' ') {
        event.preventDefault();
        setWindowMenuOpen(true);
      }
      if (command) {
        event.preventDefault();
        action(command);
      }
    };
    window.addEventListener('keydown', keydown);
    return () => window.removeEventListener('keydown', keydown);
  }, [action]);

  const working = !!state.operation || state.generation.busy || activity > 0;
  const tsaLabel =
    tsaRuntime.status === 'loading'
      ? 'chrome.tsaLoading'
      : tsaRuntime.status === 'error'
        ? 'chrome.tsaUnknown'
        : tsaRuntime.value?.running
          ? 'chrome.tsaRunning'
          : 'chrome.tsaStopped';
  return (
    <div className="app-frame" data-focused={focused}>
      <TitleBar
        title={title}
        filePath={state.file.path}
        maximized={maximized}
        captionState={captionState}
        blocked={blocked}
        windowMenuOpen={windowMenuOpen}
        setWindowMenuOpen={setWindowMenuOpen}
        onAction={action}
        onToggleNavigation={() => setDrawerOpen((value) => !value)}
        onError={reportError}
      />
      <div className="shell-sidebar">
        <Header onNavigate={navigateTo} />
      </div>
      <main className="app-main" id="main-content" tabIndex={-1}>
        {children}
      </main>
      <footer className="shell-statusbar">
        <span className="shell-task-state">
          <Circle size={6} fill="currentColor" />
          {t(working ? 'wb.working' : 'chrome.ready')}
        </span>
        <span className="shell-certificate-count">
          {certificates.status === 'ready'
            ? t('chrome.certCount', { count: certificates.items.length })
            : ''}
        </span>
        <button
          className="shell-tsa-state"
          onClick={() => navigateTo('tsa')}
          title={tsaRuntime.value?.running ? tsaRuntime.value.url : undefined}
        >
          <Circle
            size={6}
            fill="currentColor"
            className={tsaRuntime.value?.running ? 'text-[hsl(var(--success))]' : ''}
          />
          {t(tsaLabel)}
        </button>
      </footer>
      <Dialog open={drawerOpen} onOpenChange={setDrawerOpen} className="navigation-drawer">
        <DialogHeader>{t('chrome.navigation')}</DialogHeader>
        <DialogClose onClick={() => setDrawerOpen(false)} />
        <Header onNavigate={navigateTo} onDismiss={() => setDrawerOpen(false)} />
      </Dialog>
      <Dialog
        open={!!help}
        onOpenChange={(open) => {
          if (!open) setHelp(null);
        }}
      >
        <DialogHeader>{t(help === 'about' ? 'chrome.about' : 'chrome.shortcuts')}</DialogHeader>
        <DialogClose onClick={() => setHelp(null)} />
        <DialogBody>
          {help === 'about' ? (
            <div className="space-y-4">
              <div className="flex items-center gap-3">
                <ShieldCheck size={26} className="text-primary" />
                <strong>
                  RustSign{' '}
                  <span className="text-sm font-normal text-muted-foreground">{version}</span>
                </strong>
              </div>
              <p className="text-sm leading-6 text-muted-foreground">{t('chrome.aboutHint')}</p>
              <p className="text-xs text-muted-foreground">Windows · Authenticode · RFC 3161</p>
            </div>
          ) : (
            <dl className="shortcut-list">
              {(
                [
                  [t('chrome.open'), 'Ctrl+O'],
                  [t('chrome.import'), 'Ctrl+Shift+I'],
                  [t('wb.workspace'), 'Ctrl+1'],
                  [t('wb.library'), 'Ctrl+2'],
                  [t('tabs.tsa'), 'Ctrl+3'],
                  [t('chrome.windowMenu'), 'Alt+Space'],
                  [t('chrome.close'), 'Alt+F4'],
                ] as const
              ).map(([label, key]) => (
                <div key={key}>
                  <dt>{label}</dt>
                  <dd>
                    <kbd>{key}</kbd>
                  </dd>
                </div>
              ))}
            </dl>
          )}
        </DialogBody>
      </Dialog>
      <ConfirmDialog confirmation={confirmation} onClose={() => setConfirmation(null)} />
    </div>
  );
}

export function PageHeader({
  title,
  description,
  children,
}: {
  title: string;
  description?: string;
  children?: React.ReactNode;
}) {
  return (
    <header className="page-header">
      <div className="min-w-0">
        <h1>{title}</h1>
        {description && <p>{description}</p>}
      </div>
      {children && <div className="flex shrink-0 items-center gap-2">{children}</div>}
    </header>
  );
}
