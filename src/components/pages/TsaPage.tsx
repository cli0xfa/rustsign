import { useState } from 'react';
import { Play, Square, RefreshCw, Copy, Check, Server } from 'lucide-react';
import { useLanguage } from '@/contexts/LanguageContext';
import { useWorkspace } from '@/contexts/WorkspaceContext';
import { PageHeader } from '@/components/layout/AppShell';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Select } from '@/components/ui/Select';
import { Field } from '@/components/ui/Field';
import { Checkbox } from '@/components/ui/Checkbox';
import { TaskResultView } from '@/components/ui/TaskResultView';
import { canUsePrivateKey } from '@/lib/certificates';
import { errorKey } from '@/lib/errors';
import { localInputToUnix } from '@/lib/workspace';
import type { TaskResult } from '@/lib/workspace';
import * as tauri from '@/lib/tauri';
import { DIGEST_ALGORITHMS } from '@/lib/constants';
import type { LocalTsaConfig } from '@/types';

export function TsaPage() {
  const { t } = useLanguage();
  const { state, dispatch, certificates, tsaRuntime, refreshTsa, runTsa, navigate } =
    useWorkspace();
  const { config, useFixedTime, fixedDatetime } = state.tsa;
  const [result, setResult] = useState<TaskResult | null>(null);
  const [copied, setCopied] = useState(false);
  const running = tsaRuntime.value?.running === true;
  const locked = running || tsaRuntime.busy;
  const cert = certificates.items.find((item) => item.id === config.cert_id);
  const invalidPort = !Number.isInteger(config.port) || config.port < 1 || config.port > 65535;
  const invalidTime = useFixedTime && localInputToUnix(fixedDatetime) === null;
  const reason = invalidPort
    ? t('wb.invalidPort')
    : invalidTime
      ? t('wb.invalidTime')
      : !cert
        ? t('wb.certFirst')
        : !canUsePrivateKey(cert)
          ? t('wb.certUnavailable')
          : '';
  const patch = (patch: Partial<LocalTsaConfig>) =>
    dispatch({ type: 'tsa', patch: { config: { ...config, ...patch } } });
  const start = async () => {
    if (reason || locked) return;
    setResult(null);
    try {
      await runTsa(
        () =>
          tauri.startLocalTsa({
            ...config,
            fixed_time_secs: useFixedTime ? localInputToUnix(fixedDatetime) : null,
          }),
        'wb.tsaStarted',
      );
    } catch {
      /* The shared runtime retains failures across navigation. */
    }
  };
  const stop = async () => {
    setResult(null);
    try {
      await runTsa(() => tauri.stopLocalTsa(), 'wb.tsaStopped');
    } catch {
      /* The shared runtime retains failures across navigation. */
    }
  };
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(tsaRuntime.value?.url ?? '');
      setCopied(true);
    } catch {
      setResult({ tone: 'error', title: 'wb.copyFailed' });
    }
  };
  return (
    <>
      <PageHeader title={t('wb.tsa')} description={t('wb.tsaHint')}>
        <Button
          variant="ghost"
          size="icon"
          aria-label={t('wb.refresh')}
          disabled={tsaRuntime.busy}
          onClick={() => {
            void refreshTsa();
          }}
        >
          <RefreshCw className="size-4" />
        </Button>
      </PageHeader>
      <div className="page-scroll space-y-6">
        <section className="panel flex flex-wrap items-center justify-between gap-4 p-5">
          <div className="flex items-center gap-4">
            <Server className="size-6 text-muted-foreground" strokeWidth={1.5} />
            <div>
              <p className="text-xs text-muted-foreground">{t('tsa.statusLabel')}</p>
              <p className="mt-2">
                <span
                  className={`status-tag ${tsaRuntime.status === 'error' ? 'error' : running ? 'success' : ''}`}
                  role="status"
                >
                  {t(
                    tsaRuntime.status === 'loading'
                      ? 'wb.connecting'
                      : tsaRuntime.status === 'error'
                        ? 'wb.connectionFailed'
                        : running
                          ? 'wb.running'
                          : 'wb.stopped',
                  )}
                </span>
              </p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            {running && tsaRuntime.status === 'ready' && (
              <>
                <code className="select-text break-all font-mono text-xs">
                  {tsaRuntime.value?.url}
                </code>
                <Button
                  variant="ghost"
                  size="icon"
                  aria-label={t('wb.copy')}
                  onClick={() => {
                    void copy();
                  }}
                >
                  {copied ? <Check className="size-4" /> : <Copy className="size-4" />}
                </Button>
              </>
            )}
          </div>
        </section>
        {tsaRuntime.status === 'error' && (
          <div className="notice error" role="alert">
            {t(errorKey(tsaRuntime.error))}
            <Button
              variant="ghost"
              className="ml-3"
              onClick={() => {
                void refreshTsa();
              }}
            >
              {t('wb.retry')}
            </Button>
          </div>
        )}
        <div className="workbench-grid">
          <section className="panel space-y-6 p-5">
            <h2 className="section-title">{t('wb.tsaConfiguration')}</h2>
            {locked && <p className="notice">{t('wb.tsaLocked')}</p>}
            <fieldset className="space-y-5" disabled={locked}>
              <div className="field-grid">
                <Field id="tsa-port" label={t('tsa.portLabel')}>
                  <Input
                    id="tsa-port"
                    type="number"
                    min={1}
                    max={65535}
                    step={1}
                    value={Number.isNaN(config.port) ? '' : config.port}
                    aria-invalid={invalidPort}
                    onChange={(event) =>
                      patch({ port: event.target.value === '' ? NaN : Number(event.target.value) })
                    }
                  />
                  {invalidPort && <p className="text-xs text-destructive">{t('wb.invalidPort')}</p>}
                </Field>
                <Field id="tsa-bind" label={t('tsa.bindLabel')}>
                  <Select
                    id="tsa-bind"
                    value={config.bind_address}
                    onChange={(event) => patch({ bind_address: event.target.value })}
                    options={[
                      { value: '127.0.0.1', label: t('tsa.bindLocalhost') },
                      { value: '0.0.0.0', label: t('tsa.bindLan') },
                    ]}
                  />
                </Field>
              </div>
              <Field id="tsa-certificate" label={t('tsa.certLabel')}>
                <Select
                  id="tsa-certificate"
                  value={config.cert_id ?? ''}
                  placeholder={t('tsa.certPlaceholder')}
                  onChange={(event) => patch({ cert_id: event.target.value || null })}
                  options={certificates.items.map((item) => ({
                    value: item.id,
                    label: `${item.subject} · ${item.thumbprint.slice(-8)}`,
                    disabled: !canUsePrivateKey(item),
                  }))}
                />
                {certificates.status !== 'ready' && (
                  <p className="field-hint">
                    {t(
                      certificates.status === 'loading'
                        ? 'wb.loadingCertificates'
                        : 'wb.certificateLoadError',
                    )}
                  </p>
                )}
                <button
                  className="w-fit text-xs text-primary hover:underline"
                  onClick={() => navigate('certs')}
                >
                  {t('wb.addCertificate')}
                </button>
                {cert?.purposes &&
                  cert.purposes.length > 0 &&
                  !cert.purposes.includes('1.3.6.1.5.5.7.3.8') && (
                    <p className="notice warning">{t('wb.purposeWarning')}</p>
                  )}
              </Field>
              <div className="field-grid">
                <Field id="tsa-name" label={t('tsa.nameLabel')}>
                  <Input
                    id="tsa-name"
                    value={config.tsa_name ?? ''}
                    onChange={(event) => patch({ tsa_name: event.target.value || null })}
                    placeholder={t('tsa.namePlaceholder')}
                  />
                </Field>
                <Field id="tsa-digest" label={t('tsa.digestLabel')}>
                  <Select
                    id="tsa-digest"
                    options={[...DIGEST_ALGORITHMS]}
                    value={config.digest_algorithm}
                    onChange={(event) => patch({ digest_algorithm: event.target.value })}
                  />
                </Field>
              </div>
              <div className="space-y-4 border-t pt-5">
                <Checkbox
                  checked={useFixedTime}
                  label={t('tsa.fixedTimeEnable')}
                  onChange={(event) =>
                    dispatch({ type: 'tsa', patch: { useFixedTime: event.target.checked } })
                  }
                />
                {useFixedTime && (
                  <Field id="tsa-time" label={t('tsa.fixedTimeLabel')} hint={t('wb.localTime')}>
                    <Input
                      id="tsa-time"
                      type="datetime-local"
                      step={1}
                      value={fixedDatetime}
                      aria-invalid={invalidTime}
                      onChange={(event) =>
                        dispatch({ type: 'tsa', patch: { fixedDatetime: event.target.value } })
                      }
                    />
                  </Field>
                )}
                {!useFixedTime && <p className="field-hint">{t('tsa.fixedTimeHint')}</p>}
              </div>
            </fieldset>
          </section>
          <TaskResultView
            result={result ?? tsaRuntime.result}
            busy={tsaRuntime.busy ? 'tsa' : null}
          />
        </div>
      </div>
      <footer className="operation-bar">
        <p className="text-xs leading-5 text-muted-foreground">
          {tsaRuntime.busy
            ? t('wb.working')
            : running
              ? t('wb.tsaLocked')
              : reason || t('wb.ready')}
        </p>
        {running ? (
          <Button
            variant="destructive"
            loading={tsaRuntime.busy}
            onClick={() => {
              void stop();
            }}
          >
            <Square className="size-4" />
            {t('tsa.stopServer')}
          </Button>
        ) : (
          <Button
            disabled={
              !!reason ||
              tsaRuntime.busy ||
              certificates.status !== 'ready' ||
              tsaRuntime.status !== 'ready'
            }
            loading={tsaRuntime.busy}
            onClick={() => {
              void start();
            }}
          >
            <Play className="size-4" />
            {t('tsa.startServer')}
          </Button>
        )}
      </footer>
    </>
  );
}
