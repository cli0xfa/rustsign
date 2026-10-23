import { Children, cloneElement, isValidElement } from 'react';
export function Field({
  id,
  label,
  hint,
  children,
}: {
  id: string;
  label: string;
  hint?: React.ReactNode;
  children: React.ReactNode;
}) {
  const fields = Children.map(children, (child) => {
    if (
      !hint ||
      !isValidElement<{ id?: string; 'aria-describedby'?: string }>(child) ||
      child.props.id !== id
    )
      return child;
    return cloneElement(child, {
      'aria-describedby': [child.props['aria-describedby'], `${id}-hint`].filter(Boolean).join(' '),
    });
  });
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      {fields}
      {hint && (
        <div id={`${id}-hint`} className="field-hint">
          {hint}
        </div>
      )}
    </div>
  );
}
