import { CheckCircle2, CircleDashed, CircleAlert, Copy, Check } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { useLanguage } from '@/contexts/LanguageContext';
import type { TaskResult } from '@/lib/workspace';
import { Button } from './Button';
import { Disclosure } from './Disclosure';

export function TaskResultView({
  result,
  busy,
}: {
  result: TaskResult | null;
  busy?: string | null;
}) {
  const { t } = useLanguage();
  const [copiedText, setCopiedText] = useState('');
  const [copyError, setCopyError] = useState(false);
  const [resultMotionKey, setResultMotionKey] = useState(0);
  const section = useRef<HTMLElement>(null);
  const previous = useRef(result);
  useEffect(() => {
    if (result && result !== previous.current) {
      setResultMotionKey((key) => key + 1);
      section.current?.scrollIntoView({ block: 'nearest' });
    }
    previous.current = result;
  }, [result]);
  const Icon =
    result?.tone === 'success'
      ? CheckCircle2
      : result?.tone === 'error'
        ? CircleAlert
        : CircleDashed;
  const verification = result?.verification;
  const fields = verification
    ? [
        [t('results.subject'), verification.subject],
        [t('results.issuer'), verification.issuer],
        [t('results.digest'), verification.digest_algorithm],
        [
          t('results.timestamp'),
          t(verification.has_timestamp ? 'results.timestampYes' : 'results.timestampNo'),
        ],
      ]
    : [];
  const text = result
    ? [
        t(result.title),
        ...fields.map(([name, value]) => `${name}: ${value || '—'}`),
        result.details ?? '',
      ].join('\n')
    : '';
  const copied = copiedText === text && !!text;
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedText(text);
      setCopyError(false);
    } catch {
      setCopyError(true);
    }
  };
  return (
    <section ref={section} className="panel result-column p-5" aria-label={t('wb.results')}>
      <div className="mb-6 flex items-center justify-between">
        <h2 className="section-title">{t('wb.results')}</h2>
        {result && (
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
        )}
      </div>
      <div
        key={resultMotionKey}
        role={result?.tone === 'error' ? 'alert' : 'status'}
        aria-live="polite"
        className={`result-announcement space-y-3 ${result ? 'result-announcement-updated' : ''}`}
      >
        <Icon
          className={`size-6 ${result?.tone === 'success' ? 'text-[hsl(var(--success))]' : result?.tone === 'error' ? 'text-destructive' : 'text-muted-foreground'}`}
        />
        <p className="text-sm font-medium leading-6">
          {busy ? t('wb.working') : result ? t(result.title) : t('wb.resultEmpty')}
        </p>
        {!result && !busy && <p className="field-hint">{t('wb.resultEmptyHint')}</p>}
        {fields.length > 0 && (
          <dl className="space-y-3 pt-2">
            {fields.map(([label, value]) => (
              <div key={label}>
                <dt className="text-xs text-muted-foreground">{label}</dt>
                <dd className="mt-1 break-all text-sm">{value || '—'}</dd>
              </div>
            ))}
          </dl>
        )}
      </div>
      {result?.details && (
        <Disclosure label={t('wb.technicalDetails')} className="mt-6 border-t pt-4">
          <pre className="mt-3 whitespace-pre-wrap break-all font-mono text-xs leading-6 text-muted-foreground">
            {result.details}
          </pre>
        </Disclosure>
      )}
      {copyError && (
        <p role="alert" className="mt-3 text-xs text-destructive">
          {t('wb.copyFailed')}
        </p>
      )}
    </section>
  );
}
