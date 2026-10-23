import { useState } from 'react';
import { ArrowLeft, FolderOpen, Eye, EyeOff, Plus, Import } from 'lucide-react';
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
import { errorKey, normalizeError } from '@/lib/errors';
import * as tauri from '@/lib/tauri';
import type { CertGenOptions } from '@/types';
import type { TaskResult } from '@/lib/workspace';

export function GenerateCertPage() {
  const { t } = useLanguage();
  const { state, dispatch, certificates, navigate, generateCertificate, refreshCertificates } =
    useWorkspace();
  const { options, outputDir } = state.generate;
  const { busy, files, result } = state.generation;
  const [showPassword, setShowPassword] = useState(false);
  const [localResult, setLocalResult] = useState<TaskResult | null>(null);
  const patch = (patch: Partial<CertGenOptions>) =>
    dispatch({ type: 'generate', patch: { options: { ...options, ...patch } } });
  const issuer = certificates.items.find((cert) => cert.id === options.issuer_cert_id);
  const invalidName = !options.sign_cn.trim() || (options.is_root_ca && !options.root_cn.trim());
  const invalidCountry = !!options.country && !/^[a-zA-Z]{2}$/.test(options.country);
  const invalidIssuer =
    !options.is_root_ca && (!issuer || !canUsePrivateKey(issuer) || issuer.can_issue === false);
  const reason = invalidName
    ? t('wb.requiredName')
    : invalidCountry
      ? t('wb.invalidCountry')
      : invalidIssuer
        ? t('gencert.issuerHint')
        : '';
  const browse = async () => {
    try {
      const path = await tauri.openDirectoryDialog(t('gencert.outputDirLabel'));
      if (path) dispatch({ type: 'generate', patch: { outputDir: path } });
    } catch (error) {
      setLocalResult({
        tone: 'error',
        title: errorKey(error),
        details: normalizeError(error).message,
      });
    }
  };
  const imported =
    files?.sign_pfx_path &&
    certificates.items.some((cert) => cert.file_path === files.sign_pfx_path);
  const importGenerated = async () => {
    if (!files?.sign_pfx_path || busy) return;
    setLocalResult(null);
    dispatch({ type: 'generation', patch: { busy: true } });
    try {
      const res = await tauri.importCertificate(
        files.sign_pfx_path,
        state.generation.password ?? '',
      );
      if (!res.success) throw new Error(res.message);
      const items = await refreshCertificates();
      const cert = items.find((item) => item.file_path === files.sign_pfx_path);
      if (cert) dispatch({ type: 'sign', patch: { certId: cert.id } });
      dispatch({
        type: 'generation',
        patch: { result: { tone: 'success', title: 'wb.importSuccess', details: res.message } },
      });
    } catch (error) {
      dispatch({
        type: 'generation',
        patch: {
          result: { tone: 'error', title: errorKey(error), details: normalizeError(error).message },
        },
      });
    } finally {
      dispatch({ type: 'generation', patch: { busy: false } });
    }
  };
  return (
    <>
      <PageHeader title={t('wb.generate')} description={t('wb.generateHint')}>
        <Button variant="ghost" onClick={() => navigate('certs')}>
          <ArrowLeft className="size-4" />
          {t('wb.library')}
        </Button>
      </PageHeader>
      <div className="page-scroll">
        <div className="workbench-grid">
          <section className="panel p-5">
            <fieldset disabled={busy} className="space-y-6">
              <Field id="generate-mode" label={t('gencert.modeLabel')}>
                <Select
                  id="generate-mode"
                  value={options.is_root_ca ? 'root' : 'sub'}
                  options={[
                    { value: 'root', label: t('gencert.modeRoot') },
                    { value: 'sub', label: t('gencert.modeSub') },
                  ]}
                  onChange={(event) => patch({ is_root_ca: event.target.value === 'root' })}
                />
              </Field>
              {!options.is_root_ca && (
                <Field
                  id="issuer-certificate"
                  label={t('gencert.issuerCert')}
                  hint={t('gencert.issuerHint')}
                >
                  <Select
                    id="issuer-certificate"
                    value={options.issuer_cert_id ?? ''}
                    placeholder={t('gencert.selectCA')}
                    options={certificates.items.map((cert) => ({
                      value: cert.id,
                      label: `${cert.subject} · ${cert.thumbprint.slice(-8)}`,
                      disabled: !canUsePrivateKey(cert) || cert.can_issue === false,
                    }))}
                    onChange={(event) => patch({ issuer_cert_id: event.target.value || null })}
                  />
                </Field>
              )}
              <div className="space-y-5 border-t pt-5">
                <h2 className="section-title">{t('wb.identity')}</h2>
                {options.is_root_ca && (
                  <Field id="root-cn" label={t('gencert.rootCN')}>
                    <Input
                      id="root-cn"
                      value={options.root_cn}
                      onChange={(event) => patch({ root_cn: event.target.value })}
                      aria-invalid={!options.root_cn.trim()}
                    />
                  </Field>
                )}
                <Field
                  id="sign-cn"
                  label={t(options.is_root_ca ? 'gencert.signCN' : 'gencert.certCN')}
                >
                  <Input
                    id="sign-cn"
                    value={options.sign_cn}
                    onChange={(event) => patch({ sign_cn: event.target.value })}
                    aria-invalid={!options.sign_cn.trim()}
                  />
                </Field>
                <div className="field-grid">
                  <Field id="organization" label={t('gencert.orgLabel')}>
                    <Input
                      id="organization"
                      value={options.organization ?? ''}
                      onChange={(event) => patch({ organization: event.target.value || null })}
                      placeholder={t('gencert.orgPlaceholder')}
                    />
                  </Field>
                  <Field id="country" label={t('gencert.countryLabel')}>
                    <Input
                      id="country"
                      maxLength={2}
                      value={options.country ?? ''}
                      onChange={(event) =>
                        patch({ country: event.target.value.toUpperCase() || null })
                      }
                      placeholder="CN"
                      aria-invalid={invalidCountry}
                    />
                    {invalidCountry && (
                      <p className="text-xs text-destructive">{t('wb.invalidCountry')}</p>
                    )}
                  </Field>
                </div>
                <div className="field-grid">
                  <Field id="validity-years" label={t('gencert.validityLabel')}>
                    <Select
                      id="validity-years"
                      value={String(options.validity_years)}
                      options={[1, 3, 5, 10].map((value) => ({
                        value: String(value),
                        label: t('wb.years', { count: value }),
                      }))}
                      onChange={(event) => patch({ validity_years: Number(event.target.value) })}
                    />
                  </Field>
                  <Field id="pfx-password" label={t('gencert.passwordLabel')}>
                    <div className="relative">
                      <Input
                        className="pr-10"
                        id="pfx-password"
                        type={showPassword ? 'text' : 'password'}
                        value={options.pfx_password}
                        onChange={(event) => patch({ pfx_password: event.target.value })}
                        autoComplete="new-password"
                      />
                      <Button
                        type="button"
                        className="absolute right-0 top-0"
                        variant="ghost"
                        size="icon"
                        aria-label={t(showPassword ? 'wb.hidePassword' : 'wb.showPassword')}
                        onClick={() => setShowPassword(!showPassword)}
                      >
                        {showPassword ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
                      </Button>
                    </div>
                  </Field>
                </div>
              </div>
              <div className="space-y-5 border-t pt-5">
                <h2 className="section-title">{t('wb.extensions')}</h2>
                <div className="flex flex-wrap gap-x-6 gap-y-3">
                  <Checkbox
                    checked={options.code_signing_eku}
                    label={t('wb.codeSigning')}
                    onChange={(event) => patch({ code_signing_eku: event.target.checked })}
                  />
                  <Checkbox
                    checked={options.kernel_mode_eku}
                    label={t('wb.kernelSigning')}
                    onChange={(event) => patch({ kernel_mode_eku: event.target.checked })}
                  />
                  <Checkbox
                    checked={options.timestamp_eku}
                    label={t('wb.timestampSigning')}
                    onChange={(event) => patch({ timestamp_eku: event.target.checked })}
                  />
                </div>
                <details className="field-hint">
                  <summary className="cursor-pointer">{t('wb.ekuInfo')}</summary>
                  <p className="mt-3 font-mono leading-6">
                    {t('wb.codeSigning')}: 1.3.6.1.5.5.7.3.3
                    <br />
                    {t('wb.kernelSigning')}: 1.3.6.1.4.1.311.61.1.1
                    <br />
                    {t('wb.timestampSigning')}: 1.3.6.1.5.5.7.3.8
                  </p>
                </details>
                <Field id="output-directory" label={t('gencert.outputDirLabel')}>
                  <div className="flex gap-2">
                    <Input
                      id="output-directory"
                      value={outputDir}
                      onChange={(event) =>
                        dispatch({ type: 'generate', patch: { outputDir: event.target.value } })
                      }
                      placeholder={t('gencert.outputDirPlaceholder')}
                    />
                    <Button
                      variant="secondary"
                      aria-label={t('actions.browse')}
                      onClick={() => {
                        void browse();
                      }}
                    >
                      <FolderOpen className="size-4" />
                    </Button>
                  </div>
                </Field>
              </div>
            </fieldset>
            <p className="notice mt-6">{t('wb.testNotice')}</p>
            {files && (
              <section className="mt-6 space-y-4 border-t pt-5">
                <h2 className="section-title">{t('wb.generatedFiles')}</h2>
                <ul className="space-y-2">
                  {files.output_files.map((path) => (
                    <li
                      key={path}
                      className="select-text break-all font-mono text-xs leading-6 text-muted-foreground"
                    >
                      {path}
                    </li>
                  ))}
                </ul>
                <Button
                  variant="secondary"
                  disabled={busy || !!imported}
                  onClick={() => {
                    void importGenerated();
                  }}
                >
                  <Import className="size-4" />
                  {t(imported ? 'wb.importSuccess' : 'wb.importGenerated')}
                </Button>
              </section>
            )}
          </section>
          <TaskResultView result={localResult ?? result} busy={busy ? 'generate' : null} />
        </div>
      </div>
      <footer className="operation-bar">
        <p className="text-xs leading-5 text-muted-foreground">
          {busy ? t('wb.working') : reason || t('wb.ready')}
        </p>
        <Button
          disabled={!!reason || busy}
          loading={busy}
          onClick={() => {
            setLocalResult(null);
            void generateCertificate();
          }}
        >
          <Plus className="size-4" />
          {t('gencert.generate')}
        </Button>
      </footer>
    </>
  );
}
