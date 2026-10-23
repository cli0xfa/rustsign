import { useState } from 'react';
import * as Tabs from '@radix-ui/react-tabs';
import {
  FileKey2,
  FolderOpen,
  PenLine,
  Search,
  ArrowUp,
  ArrowDown,
  Trash2,
  Clock3,
  RefreshCw,
  ArrowRight,
} from 'lucide-react';
import { useLanguage } from '@/contexts/LanguageContext';
import { useWorkspace } from '@/contexts/WorkspaceContext';
import { PageHeader } from '@/components/layout/AppShell';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Select } from '@/components/ui/Select';
import { Field } from '@/components/ui/Field';
import { ConfirmDialog } from '@/components/ui/Dialog';
import type { Confirmation } from '@/components/ui/Dialog';
import { TaskResultView } from '@/components/ui/TaskResultView';
import { Disclosure } from '@/components/ui/Disclosure';
import { canUsePrivateKey, certificateValidity, isHttpUrl } from '@/lib/certificates';
import { errorKey, normalizeError } from '@/lib/errors';
import { baseName, inferSignMode } from '@/lib/utils';
import { DIGEST_ALGORITHMS, TIMESTAMP_SERVICES } from '@/lib/constants';
import * as tauri from '@/lib/tauri';
import type { FileTab, SignDraft } from '@/lib/workspace';
import type { ActionResult } from '@/types';

export function SignPage() {
  const { t } = useLanguage();
  const {
    state,
    dispatch,
    certificates,
    navigate,
    choosePeFile,
    refreshSignatures,
    runFileOperation,
    tsaRuntime,
  } = useWorkspace();
  const { file, sign, tab, operation } = state;
  const [confirmation, setConfirmation] = useState<Confirmation | null>(null);
  const [auxError, setAuxError] = useState<unknown>(null);
  const [downloading, setDownloading] = useState(false);
  const busy = operation !== null;
  const cert = certificates.items.find((item) => item.id === sign.certId);
  const timestampUrl =
    sign.timestampService === 'custom'
      ? sign.customTimestampUrl
      : sign.timestampService === 'local_tsa'
        ? tsaRuntime.status === 'ready' && tsaRuntime.value?.running
          ? tsaRuntime.value.url
          : ''
        : sign.timestampService;
  const timestampError =
    sign.timestampService === 'local_tsa' && !timestampUrl
      ? t('sign.localTsaNotRunning')
      : sign.timestampService && !isHttpUrl(timestampUrl)
        ? t('wb.invalidUrl')
        : '';
  const signReason = !file.path
    ? t('wb.selectFirst')
    : file.status !== 'ready'
      ? t(file.status === 'error' ? 'wb.signatureLoadError' : 'wb.reading')
      : certificates.status !== 'ready'
        ? t('wb.certificateLoadError')
        : !cert
          ? t('wb.certFirst')
          : !canUsePrivateKey(cert)
            ? t('wb.certUnavailable')
            : timestampError || (sign.url && !isHttpUrl(sign.url) ? t('wb.invalidUrl') : '');
  const patch = (patch: Partial<SignDraft>) => dispatch({ type: 'sign', patch });
  const browse = async () => {
    setAuxError(null);
    try {
      await choosePeFile();
    } catch (error) {
      setAuxError(error);
    }
  };
  const act = (name: string, fn: () => Promise<ActionResult>, success = 'wb.operationSuccess') => {
    void runFileOperation(
      name,
      async () => {
        const result = await fn();
        if (!result.success) throw normalizeError(result.message);
        return { tone: 'success', title: success, details: result.message };
      },
      file.revision,
    );
  };
  const signFile = () => {
    if (signReason || busy) return;
    const submit = () =>
      act(
        'sign',
        () =>
          tauri.signPeFile({
            file_path: file.path,
            cert_id: sign.certId,
            cert_path: null,
            cert_password: null,
            sign_mode: inferSignMode(file.path),
            digest_algorithm: sign.digest,
            timestamp_url: timestampUrl || null,
            description: sign.description || null,
            url: sign.url || null,
            cross_cert_path: inferSignMode(file.path) === 'driver' ? sign.crossCert || null : null,
            replace_signature: sign.mode === 'replace',
          }),
        'wb.signSuccess',
      );
    if (sign.mode === 'replace' && file.signatures.length > 0)
      setConfirmation({
        title: t('wb.overwriteTitle'),
        description: t('wb.overwriteHint'),
        target: file.path,
        onConfirm: submit,
      });
    else submit();
  };
  const verify = () => {
    void runFileOperation(
      'verify',
      async () => {
        const verification = await tauri.verifyPeSignature(file.path);
        return {
          tone: verification.valid ? 'success' : 'error',
          title: verification.valid ? 'wb.verifySuccess' : 'wb.verifyFailed',
          details: verification.message,
          verification,
        };
      },
      file.revision,
    );
  };
  const remove = (index?: number) =>
    setConfirmation({
      title: t('wb.removeTitle'),
      description: t('wb.removeHint'),
      target: `${file.path}${index === undefined ? '' : `\n#${index + 1} · ${file.signatures.find((sig) => sig.index === index)?.subject ?? ''}`}`,
      onConfirm: () =>
        act('remove', () =>
          index === undefined
            ? tauri.removePeSignature(file.path)
            : tauri.removePeSignatureAt(file.path, index),
        ),
    });
  const move = (position: number, direction: -1 | 1) => {
    const order = file.signatures.map((sig) => sig.index);
    if (position + direction < 0 || position + direction >= order.length) return;
    [order[position], order[position + direction]] = [order[position + direction], order[position]];
    act('reorder', () => tauri.reorderPeSignatures(file.path, order));
  };
  const chooseCrossCert = async () => {
    try {
      const path = await tauri.openFileDialog(t('sign.crossCertLabel'), [
        { name: 'Certificate', extensions: ['pem', 'crt', 'cer'] },
      ]);
      if (path) patch({ crossCert: path });
    } catch (error) {
      setAuxError(error);
    }
  };
  const downloadCrossCert = async () => {
    setDownloading(true);
    setAuxError(null);
    try {
      const result = await tauri.downloadCrossCert();
      if (!result.success || !result.path) throw new Error(result.message);
      patch({ crossCert: result.path });
    } catch (error) {
      setAuxError(error);
    } finally {
      setDownloading(false);
    }
  };
  const timestampField = (
    <Field id="timestamp-service" label={t('sign.timestampLabel')}>
      <Select
        id="timestamp-service"
        value={sign.timestampService}
        onChange={(event) => patch({ timestampService: event.target.value })}
        options={[
          ...TIMESTAMP_SERVICES.map((service) => ({
            value: service.value,
            label: service.label.startsWith('sign.') ? t(service.label) : service.label,
          })),
          { value: 'local_tsa', label: t('sign.timestampLocalTsa') },
        ]}
      />
      {sign.timestampService === 'custom' && (
        <Input
          aria-label={t('sign.timestampPlaceholder')}
          value={sign.customTimestampUrl}
          onChange={(event) => patch({ customTimestampUrl: event.target.value })}
          placeholder="https://"
          aria-invalid={!!timestampError}
        />
      )}
      {timestampError && (
        <p className="text-xs leading-5 text-destructive">
          {timestampError}
          {sign.timestampService === 'local_tsa' && (
            <button className="ml-2 underline underline-offset-4" onClick={() => navigate('tsa')}>
              {t('wb.tsa')}
            </button>
          )}
        </p>
      )}
    </Field>
  );
  return (
    <>
      <PageHeader title={t('wb.workspace')} description={t('wb.workspaceHint')}>
        <span className="status-tag">{t('wb.inPlace')}</span>
      </PageHeader>
      <div className="page-scroll">
        <div className="mb-6">
          {file.path ? (
            <section className="panel flex items-start gap-4 p-5" aria-label={t('sign.fileLabel')}>
              <div className="rounded-md bg-muted p-3">
                <FileKey2 className="size-6 text-muted-foreground" strokeWidth={1.5} />
              </div>
              <div className="min-w-0 flex-1">
                <div className="mb-2 flex flex-wrap items-center gap-3">
                  <h2 className="text-base font-semibold break-all">{baseName(file.path)}</h2>
                  <span className="status-tag">
                    {t(inferSignMode(file.path) === 'driver' ? 'sign.modeDriver' : 'sign.modeApp')}
                  </span>
                  <span className="text-xs text-muted-foreground">
                    {file.status === 'loading'
                      ? t('wb.reading')
                      : file.status === 'error'
                        ? t('wb.signatureLoadError')
                        : t('wb.signatures', { count: file.signatures.length })}
                  </span>
                </div>
                <p
                  className="break-all font-mono text-xs leading-5 text-muted-foreground"
                  aria-label={t('wb.fullPath')}
                >
                  {file.path}
                </p>
              </div>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => {
                  void browse();
                }}
                disabled={busy}
              >
                <FolderOpen className="size-4" />
                {t('wb.changeFile')}
              </Button>
            </section>
          ) : (
            <section className="flex items-center gap-5 rounded-lg border border-dashed border-input bg-card px-6 py-7">
              <FileKey2 className="size-9 shrink-0 text-muted-foreground" strokeWidth={1.2} />
              <div className="min-w-0 flex-1">
                <h2 className="text-base font-medium">{t('wb.dropFile')}</h2>
                <p className="mt-2 text-xs leading-5 text-muted-foreground">{t('wb.dropHint')}</p>
              </div>
              <Button
                onClick={() => {
                  void browse();
                }}
              >
                <FolderOpen className="size-4" />
                {t('wb.chooseFile')}
              </Button>
            </section>
          )}
          {auxError != null && (
            <div className="notice error mt-3" role="alert">
              {t(errorKey(auxError))}
              <details className="mt-2">
                <summary>{t('wb.technicalDetails')}</summary>
                <p className="break-all">{normalizeError(auxError).message}</p>
              </details>
            </div>
          )}
          {file.status === 'error' && (
            <div role="alert" className="notice error mt-3">
              <div className="flex items-center justify-between gap-3">
                <p>{t('wb.signatureLoadError')}</p>
                <Button
                  variant="ghost"
                  disabled={busy}
                  onClick={() => {
                    void refreshSignatures();
                  }}
                >
                  {t('wb.retry')}
                </Button>
              </div>
              <details>
                <summary className="cursor-pointer">{t('wb.technicalDetails')}</summary>
                <p className="mt-2 break-all font-mono">{file.error}</p>
              </details>
            </div>
          )}
        </div>
        <div className="workbench-grid">
          <Tabs.Root
            className="panel min-w-0"
            value={tab}
            onValueChange={(value) => dispatch({ type: 'tab', tab: value as FileTab })}
          >
            <Tabs.List className="task-tabs" aria-label={t('wb.taskTabs')}>
              <Tabs.Trigger className="task-tab" value="sign">
                {t('tabs.sign')}
              </Tabs.Trigger>
              <Tabs.Trigger className="task-tab" value="verify">
                {t('wb.inspect')}
              </Tabs.Trigger>
              <Tabs.Trigger className="task-tab" value="manage">
                {t('wb.manage')}
              </Tabs.Trigger>
            </Tabs.List>
            <Tabs.Content value="sign" className="task-content" tabIndex={0}>
              <fieldset disabled={busy} className="space-y-5">
                <Field id="sign-certificate" label={t('sign.certLabel')}>
                  <Select
                    id="sign-certificate"
                    value={sign.certId}
                    onChange={(event) => patch({ certId: event.target.value })}
                    placeholder={t('sign.certPlaceholder')}
                    options={certificates.items.map((item) => ({
                      value: item.id,
                      label: `${item.subject || item.id} · ${item.thumbprint.slice(-8)}`,
                      disabled: !canUsePrivateKey(item),
                    }))}
                  />
                  {certificates.status === 'loading' ? (
                    <p className="field-hint" role="status">
                      {t('wb.loadingCertificates')}
                    </p>
                  ) : certificates.status === 'error' ? (
                    <p className="text-xs text-destructive">{t('wb.certificateLoadError')}</p>
                  ) : certificates.items.length === 0 ? (
                    <p className="field-hint">{t('wb.noCertificates')}</p>
                  ) : null}
                  <button
                    className="inline-flex w-fit items-center gap-1 text-xs font-medium text-primary hover:underline"
                    onClick={() => navigate('certs')}
                  >
                    {t('wb.addCertificate')}
                    <ArrowRight className="size-3" />
                  </button>
                  {cert && (
                    <div className="flex flex-wrap items-center gap-2">
                      <span
                        className={`status-tag ${['expired', 'expiring', 'notYetValid'].includes(certificateValidity(cert)) ? 'warning' : ''}`}
                      >
                        {t(`wb.${certificateValidity(cert)}`)}
                      </span>
                      {cert.has_private_key == null && (
                        <span className="field-hint">{t('wb.certUnknown')}</span>
                      )}
                      {cert.purposes &&
                        cert.purposes.length > 0 &&
                        !cert.purposes.includes('1.3.6.1.5.5.7.3.3') && (
                          <p className="field-hint">{t('wb.purposeWarning')}</p>
                        )}
                    </div>
                  )}
                </Field>
                <div className="field-grid">
                  <Field id="sign-digest" label={t('sign.digestLabel')}>
                    <Select
                      id="sign-digest"
                      value={sign.digest}
                      options={[...DIGEST_ALGORITHMS]}
                      onChange={(event) => patch({ digest: event.target.value })}
                    />
                  </Field>
                  {timestampField}
                </div>
                <Field id="sign-mode" label={t('wb.signingMode')}>
                  <Select
                    id="sign-mode"
                    value={sign.mode}
                    onChange={(event) => patch({ mode: event.target.value as SignDraft['mode'] })}
                    options={[
                      { value: 'replace', label: t('sign.modeReplace') },
                      { value: 'append', label: t('sign.modeAppend') },
                    ]}
                  />
                </Field>
                <Disclosure
                  label={t('wb.advanced')}
                  hint={t('wb.optional')}
                  className="border-t pt-4"
                >
                  <div className="mt-5 space-y-5">
                    <Field id="sign-description" label={t('sign.descriptionLabel')}>
                      <Input
                        id="sign-description"
                        value={sign.description}
                        onChange={(event) => patch({ description: event.target.value })}
                        placeholder={t('sign.descriptionPlaceholder')}
                      />
                    </Field>
                    <Field id="sign-url" label={t('sign.urlLabel')}>
                      <Input
                        id="sign-url"
                        value={sign.url}
                        onChange={(event) => patch({ url: event.target.value })}
                        placeholder="https://"
                        aria-invalid={!!sign.url && !isHttpUrl(sign.url)}
                      />
                    </Field>
                    {inferSignMode(file.path) === 'driver' && (
                      <Field
                        id="cross-certificate"
                        label={t('sign.crossCertLabel')}
                        hint={t('sign.crossCertHint')}
                      >
                        <div className="flex gap-2">
                          <Input
                            id="cross-certificate"
                            value={sign.crossCert}
                            readOnly
                            placeholder={t('sign.crossCertPlaceholder')}
                          />
                          <Button
                            variant="secondary"
                            onClick={() => {
                              void chooseCrossCert();
                            }}
                          >
                            {t('actions.browse')}
                          </Button>
                          <Button
                            variant="ghost"
                            loading={downloading}
                            onClick={() => {
                              void downloadCrossCert();
                            }}
                          >
                            {t('sign.downloadCrossCert')}
                          </Button>
                        </div>
                      </Field>
                    )}
                  </div>
                </Disclosure>
              </fieldset>
            </Tabs.Content>
            <Tabs.Content value="verify" className="task-content space-y-5" tabIndex={0}>
              <div className="flex gap-3">
                <Search className="mt-1 size-5 shrink-0 text-muted-foreground" />
                <div>
                  <h2 className="section-title">{t('wb.verifyTitle')}</h2>
                  <p className="mt-3 text-sm leading-7 text-muted-foreground">
                    {t('wb.verifyHint')}
                  </p>
                </div>
              </div>
            </Tabs.Content>
            <Tabs.Content value="manage" className="task-content space-y-5" tabIndex={0}>
              {file.status === 'loading' ? (
                <p role="status" className="field-hint">
                  {t('wb.reading')}
                </p>
              ) : file.status === 'error' ? (
                <div className="notice error" role="alert">
                  {t('wb.signatureLoadError')}
                  <Button
                    className="ml-3"
                    variant="ghost"
                    onClick={() => {
                      void refreshSignatures();
                    }}
                  >
                    {t('wb.retry')}
                  </Button>
                </div>
              ) : file.signatures.length === 0 ? (
                <div className="py-5">
                  <h2 className="section-title">{t('wb.noSignatures')}</h2>
                  <p className="mt-3 field-hint">{t('wb.noSignaturesHint')}</p>
                </div>
              ) : (
                <>
                  <div className="flex items-center justify-between gap-3">
                    <p className="field-hint">{t('wb.orderHint')}</p>
                    <Button
                      variant="ghost"
                      aria-label={t('wb.refresh')}
                      size="icon"
                      disabled={busy}
                      onClick={() => {
                        void refreshSignatures();
                      }}
                    >
                      <RefreshCw className="size-4" />
                    </Button>
                  </div>
                  <ol className="divide-y">
                    {file.signatures.map((sig, index) => (
                      <li key={sig.index} className="flex items-center gap-3 py-4">
                        <span className="font-mono text-xs tabular-nums text-muted-foreground">
                          {String(index + 1).padStart(2, '0')}
                        </span>
                        <div className="min-w-0 flex-1">
                          <p className="truncate text-sm font-medium" title={sig.subject}>
                            {sig.subject}
                          </p>
                          <p className="mt-1 text-xs text-muted-foreground">
                            {sig.digest_algorithm} · {t('results.timestamp')}:{' '}
                            {t(sig.has_timestamp ? 'results.timestampYes' : 'results.timestampNo')}
                          </p>
                        </div>
                        <div className="flex shrink-0 gap-1">
                          <Button
                            variant="ghost"
                            size="icon"
                            disabled={busy || index === 0}
                            aria-label={`${t('wb.moveUp')} ${index + 1}`}
                            onClick={() => move(index, -1)}
                          >
                            <ArrowUp className="size-4" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon"
                            disabled={busy || index === file.signatures.length - 1}
                            aria-label={`${t('wb.moveDown')} ${index + 1}`}
                            onClick={() => move(index, 1)}
                          >
                            <ArrowDown className="size-4" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="text-destructive"
                            disabled={busy}
                            aria-label={`${t('wb.removeOne')} ${index + 1}`}
                            onClick={() => remove(sig.index)}
                          >
                            <Trash2 className="size-4" />
                          </Button>
                        </div>
                      </li>
                    ))}
                  </ol>
                  <div className="border-t pt-5">
                    <Button
                      variant="ghost"
                      className="text-destructive"
                      disabled={busy}
                      onClick={() => remove()}
                    >
                      <Trash2 className="size-4" />
                      {t('wb.removeAll')}
                    </Button>
                  </div>
                  <div className="space-y-4 border-t pt-5">
                    <h2 className="section-title">{t('wb.timestampActions')}</h2>
                    <fieldset disabled={busy}>{timestampField}</fieldset>
                    <div className="flex flex-wrap gap-2">
                      <Button
                        variant="secondary"
                        disabled={busy || !timestampUrl || !!timestampError}
                        onClick={() =>
                          act('timestamp', () =>
                            tauri.addTimestamp(file.path, timestampUrl, sign.digest),
                          )
                        }
                      >
                        <Clock3 className="size-4" />
                        {t('actions.addTimestamp')}
                      </Button>
                      <Button
                        variant="ghost"
                        className="text-destructive"
                        disabled={busy || !file.signatures.some((sig) => sig.has_timestamp)}
                        onClick={() =>
                          setConfirmation({
                            title: t('wb.removeTimestampTitle'),
                            description: t('wb.removeTimestampHint'),
                            target: file.path,
                            onConfirm: () =>
                              act('removeTimestamp', () => tauri.removeTimestamp(file.path)),
                          })
                        }
                      >
                        {t('actions.removeTimestamp')}
                      </Button>
                    </div>
                    {!sign.timestampService && (
                      <p className="field-hint">{t('wb.timestampRequired')}</p>
                    )}
                  </div>
                </>
              )}
            </Tabs.Content>
          </Tabs.Root>
          <TaskResultView result={state.result} busy={operation} />
        </div>
      </div>
      <footer className="operation-bar">
        <p className="min-w-0 text-xs leading-5 text-muted-foreground" role="status">
          {busy
            ? t('wb.operationBusy')
            : tab === 'sign'
              ? signReason || t('wb.ready')
              : !file.path
                ? t('wb.selectFirst')
                : t('wb.inPlace')}
        </p>
        <div className="flex shrink-0 gap-2">
          {tab === 'sign' ? (
            <Button
              disabled={!!signReason || busy}
              loading={operation === 'sign'}
              onClick={signFile}
            >
              <PenLine className="size-4" />
              {t('actions.sign')}
            </Button>
          ) : tab === 'verify' ? (
            <Button disabled={!file.path || busy} loading={operation === 'verify'} onClick={verify}>
              <Search className="size-4" />
              {t('actions.verify')}
            </Button>
          ) : null}
        </div>
      </footer>
      <ConfirmDialog confirmation={confirmation} onClose={() => setConfirmation(null)} />
    </>
  );
}
