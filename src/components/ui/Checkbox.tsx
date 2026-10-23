import { cn } from '@/lib/utils';
import { forwardRef, useEffect, useRef } from 'react';

interface CheckboxProps extends Omit<React.InputHTMLAttributes<HTMLInputElement>, 'type'> {
  indeterminate?: boolean;
  label?: string;
}

const Checkbox = forwardRef<HTMLInputElement, CheckboxProps>(
  ({ className, indeterminate, label, id, ...props }, ref) => {
    const innerRef = useRef<HTMLInputElement>(null);

    useEffect(() => {
      if (innerRef.current) {
        innerRef.current.indeterminate = indeterminate ?? false;
      }
    }, [indeterminate]);

    const inputId = id || (label ? `cb-${label}` : undefined);

    return (
      <label
        className={cn(
          'inline-flex items-center gap-2 text-sm cursor-pointer select-none',
          props.disabled && 'opacity-50 cursor-not-allowed',
          className,
        )}
      >
        <input
          type="checkbox"
          ref={(node) => {
            (innerRef as React.MutableRefObject<HTMLInputElement | null>).current = node;
            if (typeof ref === 'function') ref(node);
            else if (ref) (ref as React.MutableRefObject<HTMLInputElement | null>).current = node;
          }}
          id={inputId}
          className="h-4 w-4 rounded border border-input bg-card text-primary focus:ring-2 focus:ring-ring/30 focus:ring-offset-0 cursor-pointer transition-colors"
          {...props}
        />
        {label && <span>{label}</span>}
      </label>
    );
  },
);

Checkbox.displayName = 'Checkbox';

export { Checkbox };
