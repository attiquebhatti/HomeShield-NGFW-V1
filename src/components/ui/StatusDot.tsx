type Status = 'up' | 'down' | 'unknown' | 'ok' | 'error' | 'pending' | 'warning';

const colors: Record<Status, string> = {
  up: 'bg-success',
  ok: 'bg-success',
  down: 'bg-danger',
  error: 'bg-danger',
  unknown: 'bg-text-muted',
  pending: 'bg-warning',
  warning: 'bg-warning',
};

export function StatusDot({ status, pulse = false }: { status: Status; pulse?: boolean }) {
  return (
    <span className={`inline-block w-2 h-2 rounded-full flex-shrink-0 ${colors[status]} ${pulse ? 'animate-pulse' : ''}`} />
  );
}
