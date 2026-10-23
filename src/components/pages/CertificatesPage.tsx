import { useMemo, useState } from 'react';
import {
  Import,
  Download,
  Trash2,
  Eye,
  Plus,
  ArrowLeft,
  RefreshCw,
  Search,
  Fingerprint,
} from 'lucide-react';
import { useWorkspace } from '@/contexts/WorkspaceContext';
import { useLanguage } from '@/contexts/LanguageContext';
import { PageHeader } from '@/components/layout/AppShell';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Select } from '@/components/ui/Select';
import { Checkbox } from '@/components/ui/Checkbox';
import { ConfirmDialog } from '@/components/ui/Dialog';
import type { Confirmation } from '@/components/ui/Dialog';
import { TaskResultView } from '@/components/ui/TaskResultView';
import { CertDetailModal } from '@/components/modals/CertDetailModal';
import { AuthModal } from '@/components/modals/AuthModal';
import { certificatePurposeKeys, certificateValidity } from '@/lib/certificates';
import { errorKey, normalizeError } from '@/lib/errors';
import { EXPORT_FORMATS } from '@/lib/constants';
import * as tauri from '@/lib/tauri';
import type { CertEntry } from '@/types';
import type { TaskResult } from '@/lib/workspace';

export function CertificatesPage() {
  const { t, language } = useLanguage();
  const { certificates, refreshCertificates, navigate, chooseCertificate, state } = useWorkspace();
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState('all');
  const [sort, setSort] = useState('name');
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [format, setFormat] = useState('pem');
  const [detail, setDetail] = useState<CertEntry | null>(null);
  const [confirmation, setConfirmation] = useState<Confirmation | null>(null);
  const [result, setResult] = useState<TaskResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [pfxExport, setPfxExport] = useState<{ directory: string; ids: string[] } | null>(null);
  const visible = useMemo(() => {
    const query = search.trim().toLocaleLowerCase();
    return certificates.items
      .filter(
        (cert) =>
          (!query ||
            `${cert.subject} ${cert.issuer} ${cert.thumbprint}`
              .toLocaleLowerCase()
              .includes(query)) &&
          (filter === 'all' || certificateValidity(cert) === filter),
      )
      .sort((a, b) => {
        if (sort === 'name') return a.subject.localeCompare(b.subject);
        const left = a.not_after_secs ?? (sort === 'expiresAsc' ? Infinity : -Infinity);
        const right = b.not_after_secs ?? (sort === 'expiresAsc' ? Infinity : -Infinity);
        return sort === 'expiresAsc' ? left - right : right - left;
      });
  }, [certificates.items, search, filter, sort]);
  const selectedIds = [...selected].filter((id) =>
    certificates.items.some((cert) => cert.id === id),
  );
  const allSelected = visible.length > 0 && visible.every((cert) => selected.has(cert.id));
  const fail = (error: unknown) =>
    setResult({ tone: 'error', title: errorKey(error), details: normalizeError(error).message });
  const importCertificate = async () => {
    try {
      await chooseCertificate();
    } catch (error) {
      fail(error);
    }
  };
  const exportSelected = async () => {
    if (!selectedIds.length || busy) return;
    setBusy(true);
    setResult(null);
    try {
      const directory = await tauri.openDirectoryDialog(t('certs.exportDirectoryTitle'));
      if (!directory) return;
      if (format === 'pfx') {
        setPfxExport({ directory, ids: selectedIds });
        return;
      }
      const res = await tauri.exportCertificates(selectedIds, format, directory);
      if (!res.success) throw new Error(res.message);
      setResult({ tone: 'success', title: 'wb.exportSuccess', details: res.paths.join('\n') });
    } catch (error) {
      fail(error);
    } finally {
      setBusy(false);
    }
  };
  const deleteCertificates = async (ids: string[]) => {
    setBusy(true);
    setResult(null);
    try {
      for (const id of ids) await tauri.deleteCertificate(id);
      setSelected(new Set());
      setResult({ tone: 'success', title: 'wb.deleteSuccess' });
    } catch (error) {
      fail(error);
    } finally {
      await refreshCertificates().catch(() => {});
      setBusy(false);
    }
  };
  const askDelete = (ids: string[]) =>
    setConfirmation({
      title: t('wb.deleteTitle'),
      description: t('wb.deleteHint', { count: ids.length }),
      target: certificates.items
        .filter((cert) => ids.includes(cert.id))
        .map((cert) => `${cert.subject} · ${cert.thumbprint.slice(-8)}`)
        .join('\n'),
      onConfirm: () => {
        void deleteCertificates(ids);
      },
    });
  const date = (cert: CertEntry) =>
    cert.not_after_secs != null
      ? new Intl.DateTimeFormat(language, {
          year: 'numeric',
          month: '2-digit',
          day: '2-digit',
        }).format(new Date(cert.not_after_secs * 1000))
      : cert.not_after || '—';
  return (
    <>
      <PageHeader title={t('wb.library')} description={t('wb.libraryHint')}>
        <Button variant="ghost" size="sm" onClick={() => navigate('sign')}>
          <ArrowLeft className="size-4" />
          {t('wb.returnWorkspace')}
        </Button>
        <Button variant="secondary" onClick={() => navigate('gencert')}>
          <Plus className="size-4" />
          {t('wb.generate')}
        </Button>
      </PageHeader>
      <div className="page-scroll space-y-5">
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative min-w-48 flex-1">
            <Search className="pointer-events-none absolute left-3 top-2.5 size-4 text-muted-foreground" />
            <Input
              className="pl-9"
              aria-label={t('wb.search')}
              placeholder={t('wb.search')}
              value={search}
              onChange={(event) => {
                setSearch(event.target.value);
                setSelected(new Set());
              }}
            />
          </div>
          <Select
            aria-label={t('wb.validity')}
            value={filter}
            onChange={(event) => {
              setFilter(event.target.value);
              setSelected(new Set());
            }}
            options={[
              'all',
              'valid',
              'expiring',
              'expired',
              'notYetValid',
              'unknown',
              'unreadable',
            ].map((value) => ({ value, label: t(`wb.${value}`) }))}
          />
          <Select
            aria-label={t('wb.sort')}
            value={sort}
            onChange={(event) => setSort(event.target.value)}
            options={['nameAsc', 'expiresAsc', 'expiresDesc'].map((key) => ({
              value: key === 'nameAsc' ? 'name' : key,
              label: t(`wb.${key}`),
            }))}
          />
        </div>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-2">
            <Button
              onClick={() => {
                void importCertificate();
              }}
              disabled={busy}
            >
              <Import className="size-4" />
              {t('certs.import')}
            </Button>
            <Button
              variant="secondary"
              disabled={busy || selectedIds.length === 0 || certificates.status !== 'ready'}
              onClick={() => {
                void exportSelected();
              }}
            >
              <Download className="size-4" />
              {t('certs.exportSelected')}
            </Button>
            <Button
              variant="ghost"
              className="text-destructive"
              disabled={
                busy ||
                selectedIds.length === 0 ||
                certificates.status !== 'ready' ||
                state.operation !== null
              }
              onClick={() => askDelete(selectedIds)}
            >
              <Trash2 className="size-4" />
              {t('certs.deleteSelected')}
            </Button>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs text-muted-foreground">
              {t('wb.selected', { count: selectedIds.length })}
            </span>
            <Select
              aria-label={t('certs.exportFormat')}
              value={format}
              onChange={(event) => setFormat(event.target.value)}
              options={[...EXPORT_FORMATS]}
            />
            <Button
              variant="ghost"
              size="icon"
              aria-label={t('wb.refresh')}
              disabled={certificates.status === 'loading'}
              onClick={() => {
                void refreshCertificates().catch(() => {});
              }}
            >
              <RefreshCw className="size-4" />
            </Button>
          </div>
        </div>
        {certificates.status === 'loading' ? (
          <div className="panel space-y-4 p-6" role="status">
            <p className="field-hint">{t('wb.loadingCertificates')}</p>
            {[0, 1, 2].map((item) => (
              <div key={item} className="h-12 rounded bg-muted" />
            ))}
          </div>
        ) : certificates.status === 'error' ? (
          <div className="panel p-6" role="alert">
            <h2 className="section-title">{t('wb.certificateLoadError')}</h2>
            <p className="mt-3 field-hint">{t(errorKey(certificates.error))}</p>
            <Button
              className="mt-4"
              variant="secondary"
              onClick={() => {
                void refreshCertificates().catch(() => {});
              }}
            >
              {t('wb.retry')}
            </Button>
            <details className="mt-4 field-hint">
              <summary>{t('wb.technicalDetails')}</summary>
              <p className="mt-2 break-all">{normalizeError(certificates.error).message}</p>
            </details>
          </div>
        ) : certificates.items.length === 0 ? (
          <div className="panel flex flex-col items-center px-6 py-14 text-center">
            <Fingerprint className="mb-5 size-9 text-muted-foreground" strokeWidth={1.3} />
            <h2 className="section-title">{t('certs.emptyTitle')}</h2>
            <p className="mt-3 max-w-sm field-hint">{t('certs.emptyText')}</p>
            <Button
              className="mt-6"
              variant="secondary"
              onClick={() => {
                void importCertificate();
              }}
            >
              {t('certs.import')}
            </Button>
          </div>
        ) : visible.length === 0 ? (
          <div className="panel py-14 text-center">
            <h2 className="section-title">{t('wb.noMatches')}</h2>
            <Button
              className="mt-5"
              variant="secondary"
              onClick={() => {
                setSearch('');
                setFilter('all');
                setSelected(new Set());
              }}
            >
              {t('wb.clearFilters')}
            </Button>
          </div>
        ) : (
          <div className="panel relative overflow-x-auto">
            <table className="data-table">
              <caption className="sr-only">{t('wb.library')}</caption>
              <thead>
                <tr>
                  <th className="w-10">
                    <Checkbox
                      aria-label={t('certs.selectAll')}
                      checked={allSelected}
                      disabled={busy}
                      indeterminate={!allSelected && visible.some((cert) => selected.has(cert.id))}
                      onChange={() =>
                        setSelected(
                          allSelected ? new Set() : new Set(visible.map((cert) => cert.id)),
                        )
                      }
                    />
                  </th>
                  <th>{t('wb.name')}</th>
                  <th className="w-[22%]">
                    {t('wb.purpose')} / {t('wb.privateKey')}
                  </th>
                  <th className="w-[24%]">{t('wb.expires')}</th>
                  <th className="w-[88px]">
                    <span className="sr-only">{t('wb.actions')}</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {visible.map((cert) => {
                  const validity = certificateValidity(cert);
                  return (
                    <tr key={cert.id} data-selected={selected.has(cert.id)}>
                      <td>
                        <Checkbox
                          aria-label={t('wb.selectCertificate', { name: cert.subject })}
                          checked={selected.has(cert.id)}
                          disabled={busy}
                          onChange={() =>
                            setSelected((current) => {
                              const next = new Set(current);
                              if (next.has(cert.id)) next.delete(cert.id);
                              else next.add(cert.id);
                              return next;
                            })
                          }
                        />
                      </td>
                      <td>
                        <p className="certificate-name truncate" title={cert.subject}>
                          {cert.subject || cert.id}
                        </p>
                        <p className="mt-1 truncate text-muted-foreground" title={cert.issuer}>
                          {cert.issuer}
                        </p>
                        <p className="mt-1 font-mono tabular-nums text-muted-foreground">
                          …{cert.thumbprint.slice(-12)}
                        </p>
                      </td>
                      <td>
                        <p className="leading-5">
                          {certificatePurposeKeys(cert)
                            .map((key) => (key.startsWith('wb.') ? t(key) : key))
                            .join(' / ')}
                        </p>
                        <p
                          className={`mt-1 ${cert.has_private_key === false ? 'text-destructive' : 'text-muted-foreground'}`}
                        >
                          {t('wb.privateKey')}:{' '}
                          {t(
                            cert.has_private_key == null
                              ? 'wb.unknown'
                              : cert.has_private_key
                                ? 'wb.available'
                                : 'wb.missing',
                          )}
                        </p>
                      </td>
                      <td>
                        <p className="mb-1 tabular-nums">{date(cert)}</p>
                        <span
                          className={`status-tag ${validity === 'valid' ? 'success' : ['expired', 'unreadable'].includes(validity) ? 'error' : validity === 'expiring' || validity === 'notYetValid' ? 'warning' : ''}`}
                        >
                          {t(`wb.${validity}`)}
                        </span>
                      </td>
                      <td>
                        <div className="flex">
                          <Button
                            variant="ghost"
                            size="icon"
                            aria-label={`${t('actions.view')} ${cert.subject}`}
                            onClick={() => setDetail(cert)}
                          >
                            <Eye className="size-4" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="text-destructive"
                            aria-label={`${t('actions.delete')} ${cert.subject}`}
                            disabled={busy || state.operation !== null}
                            onClick={() => askDelete([cert.id])}
                          >
                            <Trash2 className="size-4" />
                          </Button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        {result && <TaskResultView result={result} />}
      </div>
      <footer className="operation-bar">
        <p className="text-xs text-muted-foreground">
          {t('wb.certificateCount', { count: certificates.items.length })}
        </p>
        <span className="text-xs text-muted-foreground">PFX · PEM · CRT · CER</span>
      </footer>
      {detail && <CertDetailModal cert={detail} onClose={() => setDetail(null)} />}
      {confirmation && (
        <ConfirmDialog confirmation={confirmation} onClose={() => setConfirmation(null)} />
      )}
      {pfxExport && (
        <AuthModal
          ingress={{
            mode: 'exportPfx',
            filePath: '',
            contextValue: pfxExport.directory,
            exportIds: pfxExport.ids,
          }}
          onClose={() => setPfxExport(null)}
          onSuccess={(message) =>
            setResult({ tone: 'success', title: 'wb.exportSuccess', details: message })
          }
        />
      )}
    </>
  );
}
