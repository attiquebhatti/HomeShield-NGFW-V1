import { describe, it, expect } from 'vitest';
import { policyFingerprint, diffPolicies } from './configdiff.mjs';

const p = (over = {}) => ({ id: '1', name: 'R', enabled: true, action: 'allow', priority: 100, tags: [], ...over });

describe('policyFingerprint', () => {
  it('is stable regardless of timestamps and tag order', () => {
    const a = policyFingerprint(p({ tags: ['b', 'a'], created_at: 'x', updated_at: 'y' }));
    const b = policyFingerprint(p({ tags: ['a', 'b'], created_at: 'z' }));
    expect(a).toBe(b);
  });

  it('changes when an enforcement field changes', () => {
    expect(policyFingerprint(p({ action: 'allow' }))).not.toBe(policyFingerprint(p({ action: 'deny' })));
    expect(policyFingerprint(p({ enabled: true }))).not.toBe(policyFingerprint(p({ enabled: false })));
  });
});

describe('diffPolicies', () => {
  it('reports no changes when identical', () => {
    const cfg = [p({ id: '1' }), p({ id: '2' })];
    expect(diffPolicies(cfg, cfg)).toEqual({ added: 0, removed: 0, modified: 0, pending: 0 });
  });

  it('counts additions, removals and modifications', () => {
    const running = [p({ id: '1', action: 'allow' }), p({ id: '2' })];
    const candidate = [p({ id: '1', action: 'deny' }), p({ id: '3' })]; // 1 modified, 2 removed, 3 added
    expect(diffPolicies(candidate, running)).toEqual({ added: 1, removed: 1, modified: 1, pending: 3 });
  });

  it('treats an empty running config as everything pending (never committed)', () => {
    expect(diffPolicies([p({ id: '1' }), p({ id: '2' })], [])).toMatchObject({ added: 2, pending: 2 });
  });
});
