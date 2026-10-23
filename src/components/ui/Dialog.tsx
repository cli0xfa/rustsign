import * as Primitive from '@radix-ui/react-dialog';
import * as Alert from '@radix-ui/react-alert-dialog';
import { X } from 'lucide-react';
import { useRef } from 'react';
import { cn } from '@/lib/utils';
import { useLanguage } from '@/contexts/LanguageContext';
import { Button } from './Button';

export function Dialog({
  open,
  onOpenChange,
  onCloseComplete,
  children,
  className,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onCloseComplete?: () => void;
  children: React.ReactNode;
  className?: string;
}) {
  const opener = useRef<HTMLElement | null>(null);
  return (
    <Primitive.Root open={open} onOpenChange={onOpenChange}>
      <Primitive.Portal>
        <Primitive.Overlay className="dialog-overlay" />
        <Primitive.Content
          className={cn('dialog-content', className)}
          aria-describedby={undefined}
          onOpenAutoFocus={() => {
            opener.current = document.activeElement as HTMLElement | null;
          }}
          onCloseAutoFocus={(event) => {
            if (opener.current?.isConnected) {
              event.preventDefault();
              opener.current.focus();
            }
            onCloseComplete?.();
          }}
        >
          {children}
        </Primitive.Content>
      </Primitive.Portal>
    </Primitive.Root>
  );
}
export function DialogHeader({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn('border-b px-6 py-5 pr-12', className)}>
      <Primitive.Title className="text-lg font-semibold text-balance">{children}</Primitive.Title>
    </div>
  );
}
export function DialogBody({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return <div className={cn('space-y-5 px-6 py-5', className)}>{children}</div>;
}
export function DialogFooter({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn('flex justify-end gap-3 border-t px-6 py-4', className)}>{children}</div>
  );
}
export function DialogClose({ onClick }: { onClick: () => void }) {
  const { t } = useLanguage();
  return (
    <Primitive.Close asChild>
      <Button
        aria-label={t('wb.close')}
        variant="ghost"
        size="icon"
        className="absolute right-3 top-3"
        onClick={onClick}
      >
        <X className="size-4" />
      </Button>
    </Primitive.Close>
  );
}
export interface Confirmation {
  title: string;
  description: string;
  target: string;
  onConfirm: () => void;
}
export function ConfirmDialog({
  confirmation,
  onClose,
}: {
  confirmation: Confirmation | null;
  onClose: () => void;
}) {
  const { t } = useLanguage();
  const opener = useRef<HTMLElement | null>(null);
  return (
    <Alert.Root
      open={!!confirmation}
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
    >
      <Alert.Portal>
        <Alert.Overlay className="dialog-overlay" />
        <Alert.Content
          className="dialog-content"
          onOpenAutoFocus={() => {
            opener.current = document.activeElement as HTMLElement | null;
          }}
          onCloseAutoFocus={(event) => {
            if (opener.current?.isConnected) {
              event.preventDefault();
              opener.current.focus();
            }
          }}
        >
          <div className="space-y-4 p-6">
            <Alert.Title className="text-lg font-semibold">{confirmation?.title}</Alert.Title>
            <Alert.Description className="text-sm leading-6 text-muted-foreground">
              {confirmation?.description}
            </Alert.Description>
            <p className="rounded-md bg-muted p-3 font-mono text-xs leading-6 break-all">
              {confirmation?.target}
            </p>
          </div>
          <div className="flex justify-end gap-3 border-t px-6 py-4">
            <Alert.Cancel asChild>
              <Button variant="secondary">{t('modal.cancel')}</Button>
            </Alert.Cancel>
            <Alert.Action asChild>
              <Button variant="destructive" onClick={() => confirmation?.onConfirm()}>
                {t('wb.confirm')}
              </Button>
            </Alert.Action>
          </div>
        </Alert.Content>
      </Alert.Portal>
    </Alert.Root>
  );
}
