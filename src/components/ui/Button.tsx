import { ReactNode, ButtonHTMLAttributes } from 'react';

type Variant = 'primary' | 'secondary' | 'danger' | 'ghost' | 'success';
type Size = 'sm' | 'md' | 'lg';

const variants: Record<Variant, string> = {
  primary: 'bg-brand-gold hover:bg-brand-gold-bright text-brand-main border border-brand-gold font-semibold shadow-gold-sm hover:shadow-gold-md',
  secondary: 'bg-brand-steel/60 hover:bg-brand-steel text-text-secondary border border-border-strong hover:text-text-primary',
  danger: 'bg-danger/15 hover:bg-danger/25 text-danger border border-danger/30',
  ghost: 'bg-transparent hover:bg-brand-slate text-text-muted hover:text-text-primary border border-transparent',
  success: 'bg-success/15 hover:bg-success/25 text-success border border-success/30',
};

const sizes: Record<Size, string> = {
  sm: 'px-3 py-1.5 text-xs',
  md: 'px-4 py-2 text-sm',
  lg: 'px-5 py-2.5 text-sm',
};

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  children: ReactNode;
  variant?: Variant;
  size?: Size;
  loading?: boolean;
}

export function Button({ children, variant = 'secondary', size = 'md', loading, className = '', disabled, ...props }: ButtonProps) {
  return (
    <button
      className={`
        inline-flex items-center gap-2 font-medium rounded-lg transition-all duration-150
        disabled:opacity-50 disabled:cursor-not-allowed
        ${variants[variant]} ${sizes[size]} ${className}
      `}
      disabled={disabled || loading}
      {...props}
    >
      {loading && (
        <svg className="animate-spin w-3.5 h-3.5" fill="none" viewBox="0 0 24 24">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
        </svg>
      )}
      {children}
    </button>
  );
}
