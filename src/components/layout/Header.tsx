import { FileKey2, Fingerprint, Server, PanelLeftClose } from 'lucide-react';
import { useWorkspace } from '@/contexts/WorkspaceContext';
import { useLanguage } from '@/contexts/LanguageContext';
import type { PageKey } from '@/types';

export function Header({
  onNavigate,
  onDismiss,
}: {
  onNavigate: (page: PageKey) => void;
  onDismiss?: () => void;
}) {
  const { page } = useWorkspace();
  const { t } = useLanguage();
  const items = [
    { id: 'sign' as const, label: t('wb.workspace'), Icon: FileKey2 },
    { id: 'certs' as const, label: t('wb.library'), Icon: Fingerprint },
    { id: 'tsa' as const, label: t('tabs.tsa'), Icon: Server },
  ];
  return (
    <aside className="sidebar">
      <div className="sidebar-caption">
        <span>{t('chrome.local')}</span>
        {onDismiss && (
          <button
            className="drawer-dismiss"
            aria-label={t('chrome.toggleNavigation')}
            onClick={onDismiss}
          >
            <PanelLeftClose size={16} />
          </button>
        )}
      </div>
      <nav aria-label={t('chrome.navigation')} className="space-y-1">
        {items.map(({ id, label, Icon }) => (
          <button
            key={id}
            className="nav-item"
            title={label}
            aria-current={
              page === id || (id === 'certs' && page === 'gencert') ? 'page' : undefined
            }
            onClick={() => onNavigate(id)}
          >
            <Icon className="size-4 shrink-0" strokeWidth={1.7} />
            <span className="nav-label">{label}</span>
          </button>
        ))}
      </nav>
      <div className="sidebar-footnote">
        <span>Windows</span>
        <span>Authenticode</span>
      </div>
    </aside>
  );
}
