import { describe, it, expect } from 'vitest';
import { renderPrometheus, groupSamples } from './metrics.mjs';

describe('renderPrometheus', () => {
  it('renders HELP, TYPE and samples', () => {
    const out = renderPrometheus([
      { name: 'homeshield_up', help: 'Server up', type: 'gauge', samples: [{ value: 1 }] },
    ]);
    expect(out).toContain('# HELP homeshield_up Server up');
    expect(out).toContain('# TYPE homeshield_up gauge');
    expect(out).toContain('homeshield_up 1');
    expect(out.endsWith('\n')).toBe(true);
  });

  it('renders labels in Prometheus format', () => {
    const out = renderPrometheus([
      { name: 'hs_events', type: 'gauge', samples: [
        { value: 5, labels: { action: 'deny', proto: 'tcp' } },
        { value: 2, labels: { action: 'allow', proto: 'udp' } },
      ] },
    ]);
    expect(out).toContain('hs_events{action="deny",proto="tcp"} 5');
    expect(out).toContain('hs_events{action="allow",proto="udp"} 2');
  });

  it('escapes label values and help text', () => {
    const out = renderPrometheus([
      { name: 'hs_x', help: 'line\nbreak', type: 'gauge', samples: [{ value: 1, labels: { name: 'a"b\\c' } }] },
    ]);
    expect(out).toContain('# HELP hs_x line\\nbreak');
    expect(out).toContain('hs_x{name="a\\"b\\\\c"} 1');
  });

  it('skips non-finite samples', () => {
    const out = renderPrometheus([
      { name: 'hs_y', type: 'gauge', samples: [{ value: NaN }, { value: null }, { value: 3 }] },
    ]);
    expect(out).not.toContain('hs_y NaN');
    expect(out).toContain('hs_y 3');
  });
});

describe('groupSamples', () => {
  it('maps grouped rows to labelled samples', () => {
    const rows = [{ action: 'blocked', count: 10 }, { action: 'allowed', count: 90 }];
    expect(groupSamples(rows, 'action')).toEqual([
      { value: 10, labels: { action: 'blocked' } },
      { value: 90, labels: { action: 'allowed' } },
    ]);
  });

  it('defaults missing labels and values', () => {
    expect(groupSamples([{ count: 5 }], 'severity')).toEqual([{ value: 5, labels: { severity: 'unknown' } }]);
    expect(groupSamples([{ severity: 'high' }], 'severity')).toEqual([{ value: 0, labels: { severity: 'high' } }]);
  });
});
