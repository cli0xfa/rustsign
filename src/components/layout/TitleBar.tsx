import { useLayoutEffect, useRef } from 'react';
import * as Menubar from '@radix-ui/react-menubar';
import * as Dropdown from '@radix-ui/react-dropdown-menu';
import {
  Check,
  ChevronRight,
  Menu,
  Minus,
  PanelLeft,
  ShieldCheck,
  Square,
  Copy,
  X,
} from 'lucide-react';
import { useLanguage } from '@/contexts/LanguageContext';
import { useTheme } from '@/contexts/ThemeContext';
import { useWorkspace } from '@/contexts/WorkspaceContext';
import { desktopWindow, syncWindowChrome, windowAction } from '@/lib/desktop';

export type ShellAction =
  | 'open'
  | 'import'
  | 'exit'
  | 'sign'
  | 'certs'
  | 'tsa'
  | 'gencert'
  | 'shortcuts'
  | 'about';
type MenuKey = 'file' | 'view' | 'tools' | 'help';
const menuKeys: MenuKey[] = ['file', 'view', 'tools', 'help'];

function MenuItems({
  menu,
  mode,
  onAction,
}: {
  menu: MenuKey;
  mode: 'menubar' | 'dropdown';
  onAction: (action: ShellAction) => void;
}) {
  const ui = mode === 'menubar' ? Menubar : Dropdown;
  const { t, language, setLanguage } = useLanguage();
  const { resolved, setTheme } = useTheme();
  const { state } = useWorkspace();
  const entry = (label: string, action: ShellAction, shortcut?: string, disabled = false) => (
    <ui.Item className="menu-item" disabled={disabled} onSelect={() => onAction(action)}>
      <span>{label}</span>
      {shortcut && <kbd>{shortcut}</kbd>}
    </ui.Item>
  );
  if (menu === 'file')
    return (
      <>
        {entry(t('chrome.open'), 'open', 'Ctrl+O', !!state.operation)}
        {entry(t('chrome.import'), 'import', 'Ctrl+Shift+I')}
        <ui.Separator className="menu-separator" />
        {entry(t('chrome.exit'), 'exit', 'Alt+F4')}
      </>
    );
  if (menu === 'tools')
    return (
      <>
        {entry(t('wb.generate'), 'gencert')}
        {entry(t('tabs.tsa'), 'tsa')}
      </>
    );
  if (menu === 'help')
    return (
      <>
        {entry(t('chrome.shortcuts'), 'shortcuts', 'F1')}
        {entry(t('chrome.about'), 'about')}
      </>
    );
  return (
    <>
      {entry(t('wb.workspace'), 'sign', 'Ctrl+1')}
      {entry(t('wb.library'), 'certs', 'Ctrl+2')}
      {entry(t('tabs.tsa'), 'tsa', 'Ctrl+3')}
      <ui.Separator className="menu-separator" />
      <ui.Label className="menu-label">{t('chrome.appearance')}</ui.Label>
      <ui.RadioGroup
        value={resolved}
        onValueChange={(value) => setTheme(value === 'light' ? 'light' : 'dark')}
      >
        {(['dark', 'light'] as const).map((value) => (
          <ui.RadioItem className="menu-item menu-radio" key={value} value={value}>
            <ui.ItemIndicator className="menu-check">
              <Check size={14} />
            </ui.ItemIndicator>
            {t(`theme.${value}`)}
          </ui.RadioItem>
        ))}
      </ui.RadioGroup>
      <ui.Separator className="menu-separator" />
      <ui.Label className="menu-label">{t('chrome.language')}</ui.Label>
      <ui.RadioGroup
        value={language}
        onValueChange={(value) => setLanguage(value === 'en' ? 'en' : 'zh-CN')}
      >
        {(['zh-CN', 'en'] as const).map((value) => (
          <ui.RadioItem className="menu-item menu-radio" key={value} value={value}>
            <ui.ItemIndicator className="menu-check">
              <Check size={14} />
            </ui.ItemIndicator>
            {value === 'en' ? 'English' : '简体中文'}
          </ui.RadioItem>
        ))}
      </ui.RadioGroup>
    </>
  );
}

interface TitleBarProps {
  title: string;
  filePath: string;
  maximized: boolean;
  captionState: string;
  blocked: boolean;
  windowMenuOpen: boolean;
  setWindowMenuOpen: (open: boolean) => void;
  onAction: (action: ShellAction) => void;
  onToggleNavigation: () => void;
  onError: (error: unknown) => void;
}

export function TitleBar({
  title,
  filePath,
  maximized,
  captionState,
  blocked,
  windowMenuOpen,
  setWindowMenuOpen,
  onAction,
  onToggleNavigation,
  onError,
}: TitleBarProps) {
  const { t } = useLanguage();
  const maximizeButton = useRef<HTMLButtonElement>(null);
  useLayoutEffect(() => {
    let mounted = true;
    const sync = () => {
      const rect = maximizeButton.current?.getBoundingClientRect();
      if (rect)
        void syncWindowChrome(
          { x: rect.x, y: rect.y, width: rect.width, height: rect.height },
          blocked,
        ).catch((error) => {
          if (mounted) onError(error);
        });
    };
    sync();
    const observer = new ResizeObserver(sync);
    observer.observe(document.documentElement);
    window.addEventListener('resize', sync);
    const unsubscribe = desktopWindow()?.onScaleChanged?.(sync);
    return () => {
      mounted = false;
      observer.disconnect();
      window.removeEventListener('resize', sync);
      void unsubscribe?.then((off) => off()).catch(onError);
    };
  }, [blocked, onError]);
  const act = (action: Parameters<typeof windowAction>[0]) => {
    void windowAction(action).catch(onError);
  };
  const windowItem = (
    action: 'restore' | 'move' | 'resize' | 'minimize' | 'maximize',
    disabled = false,
  ) => (
    <Dropdown.Item className="menu-item" disabled={disabled} onSelect={() => act(action)}>
      {t(`chrome.${action}`)}
    </Dropdown.Item>
  );
  return (
    <header className="titlebar">
      <a href="#main-content" className="skip-link">
        {t('wb.workspace')}
      </a>
      <button
        className="navigation-toggle"
        aria-label={t('chrome.toggleNavigation')}
        onClick={onToggleNavigation}
      >
        <PanelLeft size={16} />
      </button>
      <Dropdown.Root open={windowMenuOpen} onOpenChange={setWindowMenuOpen}>
        <Dropdown.Trigger className="titlebar-brand" aria-label={t('chrome.windowMenu')}>
          <ShieldCheck size={18} strokeWidth={1.6} />
          <span>RustSign</span>
        </Dropdown.Trigger>
        <Dropdown.Portal>
          <Dropdown.Content className="menu-content" align="start" sideOffset={3}>
            {windowItem('restore', !maximized)}
            {windowItem('move', maximized)}
            {windowItem('resize', maximized)}
            {windowItem('minimize')}
            {windowItem('maximize', maximized)}
            <Dropdown.Separator className="menu-separator" />
            <Dropdown.Item className="menu-item" onSelect={() => onAction('exit')}>
              <span>{t('chrome.close')}</span>
              <kbd>Alt+F4</kbd>
            </Dropdown.Item>
          </Dropdown.Content>
        </Dropdown.Portal>
      </Dropdown.Root>
      <Menubar.Root className="application-menubar" aria-label={t('chrome.menu')}>
        {menuKeys.map((menu) => (
          <Menubar.Menu key={menu}>
            <Menubar.Trigger className="menubar-trigger">{t(`chrome.${menu}`)}</Menubar.Trigger>
            <Menubar.Portal>
              <Menubar.Content className="menu-content" align="start" sideOffset={3}>
                <MenuItems menu={menu} mode="menubar" onAction={onAction} />
              </Menubar.Content>
            </Menubar.Portal>
          </Menubar.Menu>
        ))}
      </Menubar.Root>
      <Dropdown.Root>
        <Dropdown.Trigger className="compact-menu-trigger" aria-label={t('chrome.menu')}>
          <Menu size={16} />
        </Dropdown.Trigger>
        <Dropdown.Portal>
          <Dropdown.Content className="menu-content" sideOffset={3} align="start">
            {menuKeys.map((menu) => (
              <Dropdown.Sub key={menu}>
                <Dropdown.SubTrigger className="menu-item">
                  <span>{t(`chrome.${menu}`)}</span>
                  <ChevronRight size={14} />
                </Dropdown.SubTrigger>
                <Dropdown.Portal>
                  <Dropdown.SubContent className="menu-content" sideOffset={4} alignOffset={-4}>
                    <MenuItems menu={menu} mode="dropdown" onAction={onAction} />
                  </Dropdown.SubContent>
                </Dropdown.Portal>
              </Dropdown.Sub>
            ))}
          </Dropdown.Content>
        </Dropdown.Portal>
      </Dropdown.Root>
      <div
        className="titlebar-drag"
        data-tauri-drag-region
        title={filePath || t('chrome.windowHint')}
        onContextMenu={(event) => {
          event.preventDefault();
          setWindowMenuOpen(true);
        }}
      >
        <span className="titlebar-document" data-tauri-drag-region>
          {title}
        </span>
      </div>
      <div className="window-controls">
        <button
          aria-label={t('chrome.minimize')}
          title={t('chrome.minimize')}
          onClick={() => act('minimize')}
        >
          <Minus size={14} />
        </button>
        <button
          ref={maximizeButton}
          aria-label={t(maximized ? 'chrome.restore' : 'chrome.maximize')}
          title={t(maximized ? 'chrome.restore' : 'chrome.maximize')}
          data-caption-state={captionState}
          onClick={() => act('toggle')}
        >
          {maximized ? <Copy size={12} /> : <Square size={12} />}
        </button>
        <button
          className="window-close"
          aria-label={t('chrome.close')}
          title={t('chrome.close')}
          onClick={() => onAction('exit')}
        >
          <X size={16} />
        </button>
      </div>
    </header>
  );
}
