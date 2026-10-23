import {
  Dialog,
  DialogHeader,
  DialogBody,
  DialogClose,
  DialogFooter,
} from '@/components/ui/Dialog';
import { Button } from '@/components/ui/Button';
import { useLanguage } from '@/contexts/LanguageContext';
import { useWorkspace } from '@/contexts/WorkspaceContext';
import { certificatePurposeKeys, canUsePrivateKey } from '@/lib/certificates';
import type { CertEntry } from '@/types';
import { useState } from 'react';

export function CertDetailModal({ cert, onClose }: { cert: CertEntry; onClose: () => void }) {
  const [open, setOpen] = useState(true);
  const { t } = useLanguage();
  const { dispatch, navigate, state } = useWorkspace();
  const rows = [
    ['certs.detail.subject', cert.subject],
    ['certs.detail.issuer', cert.issuer],
    ['certs.detail.serial', cert.serial_number],
    ['certs.detail.validFrom', cert.not_before],
    ['certs.detail.validTo', cert.not_after],
    ['certs.detail.algorithm', cert.signature_algorithm],
    ['certs.detail.thumbprint', cert.thumbprint],
    ['certs.detail.filePath', cert.file_path],
    [
      'wb.purpose',
      certificatePurposeKeys(cert)
        .map((key) => (key.startsWith('wb.') ? t(key) : key))
        .join(' / '),
    ],
    [
      'wb.privateKey',
      t(
        cert.has_private_key == null
          ? 'wb.unknown'
          : cert.has_private_key
            ? 'wb.available'
            : 'wb.missing',
      ),
    ],
  ];
  return (
    <Dialog open={open} onOpenChange={setOpen} onCloseComplete={onClose} className="drawer">
      <DialogHeader>{t('certs.detailTitle')}</DialogHeader>
      <DialogClose onClick={() => setOpen(false)} />
      <DialogBody>
        <dl className="space-y-5">
          {rows.map(([label, value]) => (
            <div key={label}>
              <dt className="mb-2 text-xs text-muted-foreground">{t(label)}</dt>
              <dd className="select-text break-all text-sm leading-6">{value || '—'}</dd>
            </div>
          ))}
        </dl>
        {cert.read_error && <div className="notice error">{cert.read_error}</div>}
      </DialogBody>
      <DialogFooter>
        <Button variant="secondary" onClick={() => setOpen(false)}>
          {t('wb.close')}
        </Button>
        <Button
          disabled={!canUsePrivateKey(cert) || state.operation !== null}
          onClick={() => {
            dispatch({ type: 'sign', patch: { certId: cert.id } });
            navigate('sign');
            setOpen(false);
          }}
        >
          {t('wb.returnWorkspace')}
        </Button>
      </DialogFooter>
    </Dialog>
  );
}
