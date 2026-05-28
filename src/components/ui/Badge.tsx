import { ReactNode } from 'react';

type Variant = 'default' | 'success' | 'danger' | 'warning' | 'info' | 'neutral' | 'gold';

const variants: Record<Variant, string> = {
  default: 'bg-brand-steel/50 text-text-secondary',
  success: 'bg-success/15 text-success border border-success/25',
  danger: 'bg-danger/15 text-danger border border-danger/25',
  warning: 'bg-warning/15 text-warning border border-warning/25',
  info: 'bg-info/15 text-info border border-info/25',
  neutral: 'bg-brand-slate text-text-muted border border-border-muted',
  gold: 'bg-brand-gold/15 text-brand-gold-bright border border-brand-gold/30',
};

interface BadgeProps {
  children: ReactNode;
  variant?: Variant;
  className?: string;
}

export function Badge({ children, variant = 'default', className = '' }: BadgeProps) {
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${variants[variant]} ${className}`}>
      {children}
    </span>
  );
}
