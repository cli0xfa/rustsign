import { useState } from 'react';
import {
  Dialog,
  DialogHeader,
  DialogBody,
  DialogFooter,
  DialogClose,
} from '@/components/ui/Dialog';
import { Input } from '@/components/ui/Input';
import { Button } from '@/components/ui/Button';
import { ResultPanel } from '@/components/ui/ResultPanel';
import { useLanguage } from '@/contexts/LanguageContext';
import * as tauri from '@/lib/tauri';
import type { AuthModalMode, ExportBatchResult } from '@/types';
import { errorKey, normalizeError } from '@/lib/errors';

interface AuthModalIngress {
  mode: AuthModalMode;
  filePath: string;
  contextValue: string;
  exportIds?: string[];
}

interface AuthModalProps {
  ingress: AuthModalIngress;
  onClose: () => void;
  onSuccess: (message: string) => void;
}

export function AuthModal({ ingress, onClose, onSuccess }: AuthModalProps) {
  const { t } = useLanguage();
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [errorDetails, setErrorDetails] = useState('');

  const isImport = ingress.mode === 'import';

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      if (isImport) {
        const result = await tauri.importCertificate(ingress.filePath, password || undefined);
        if (!result.success) {
          setError(errorKey(result.message));
          setErrorDetails(result.message);
          return;
        }
        onSuccess(result.message);
        onClose();
      } else {
        const result = (await tauri.exportCertificates(
          ingress.exportIds ?? [],
          'pfx',
          ingress.contextValue,
          password || undefined,
        )) as ExportBatchResult;
        if (!result.success) {
          setError(errorKey(result.message));
          setErrorDetails(result.message);
          return;
        }
        onSuccess(result.message);
        onClose();
      }
    } catch (err) {
      setError(errorKey(err));
      setErrorDetails(normalizeError(err).message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Dialog
      open={true}
      onOpenChange={() => {
        if (!loading) onClose();
      }}
    >
      <DialogClose
        onClick={() => {
          if (!loading) onClose();
        }}
      />
      <form onSubmit={handleSubmit}>
        <DialogHeader>{isImport ? t('modal.importTitle') : t('modal.exportTitle')}</DialogHeader>
        <DialogBody>
          <p className="text-sm text-muted-foreground">
            {isImport ? t('modal.importDescription') : t('modal.exportDescription')}
          </p>

          <div className="rounded-lg border bg-muted/50 p-3 text-sm">
            <div className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-1">
              {isImport ? t('modal.fileLabel') : t('modal.folderLabel')}
            </div>
            <div className="font-mono text-xs break-all">{ingress.contextValue}</div>
          </div>

          <div className="space-y-1.5">
            <label htmlFor="auth-password" className="text-sm font-medium">
              {t('modal.passwordLabel')}
            </label>
            <Input
              id="auth-password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder={t('modal.passwordPlaceholder')}
              autoFocus
            />
            <p className="text-xs text-muted-foreground">{t('modal.passwordHint')}</p>
          </div>

          {error && (
            <div role="alert">
              <ResultPanel variant="error" message={t(error)} />
              <details className="mt-3 text-xs text-muted-foreground">
                <summary>{t('wb.technicalDetails')}</summary>
                <p className="mt-2 break-all">{errorDetails}</p>
              </details>
            </div>
          )}
        </DialogBody>
        <DialogFooter>
          <Button type="button" variant="ghost" onClick={onClose} disabled={loading}>
            {t('modal.cancel')}
          </Button>
          <Button type="submit" loading={loading}>
            {isImport ? t('modal.importConfirm') : t('modal.exportConfirm')}
          </Button>
        </DialogFooter>
      </form>
    </Dialog>
  );
}
