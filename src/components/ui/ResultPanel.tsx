import { cn } from '@/lib/utils';
import type { ResultTone } from '@/types';

interface ResultPanelProps {
  variant: ResultTone;
  message: string;
  className?: string;
}

const variantStyles: Record<ResultTone, string> = {
  success:
    'bg-[hsl(var(--success-bg))] border-[hsl(var(--success-border))] text-[hsl(var(--success))]',
  error: 'bg-[hsl(var(--error-bg))] border-[hsl(var(--error-border))] text-[hsl(var(--error))]',
  info: 'bg-[hsl(var(--info-bg))] border-[hsl(var(--info-border))] text-[hsl(var(--info))]',
};

export function ResultPanel({ variant, message, className }: ResultPanelProps) {
  if (!message) return null;

  return (
    <div
      className={cn(
        'rounded-lg border px-4 py-3 text-sm whitespace-pre-wrap break-words animate-slide-up',
        variantStyles[variant],
        className,
      )}
    >
      {message}
    </div>
  );
}
