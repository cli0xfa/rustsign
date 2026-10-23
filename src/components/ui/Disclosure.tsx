import { useId, useState } from 'react';
import { ChevronDown } from 'lucide-react';
import { cn } from '@/lib/utils';

export function Disclosure({
  label,
  hint,
  children,
  className,
  defaultOpen = false,
}: {
  label: string;
  hint?: string;
  children: React.ReactNode;
  className?: string;
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const id = useId();
  const triggerId = `${id}-trigger`;
  const panelId = `${id}-panel`;

  return (
    <section className={cn('disclosure', className)}>
      <button
        id={triggerId}
        type="button"
        className="disclosure-trigger"
        aria-expanded={open}
        aria-controls={panelId}
        onClick={() => setOpen((value) => !value)}
      >
        <ChevronDown aria-hidden="true" className="disclosure-icon size-4 shrink-0" />
        <span>{label}</span>
        {hint && <span className="text-xs">{hint}</span>}
      </button>
      <div
        id={panelId}
        className="disclosure-panel"
        data-open={open}
        aria-hidden={!open}
        inert={!open}
        role="region"
        aria-labelledby={triggerId}
      >
        <div className="disclosure-panel-inner">{children}</div>
      </div>
    </section>
  );
}
