/**
 * Candidate-vs-running config diff for the HomeShield firewall rulebase.
 *
 * The "running" config is the policy set as of the last confirmed commit;
 * the "candidate" is the current editable policy table. The diff drives the
 * "N uncommitted changes" indicator and the Commit / Revert workflow. Pure —
 * unit tested in configdiff.test.mjs.
 */

const FIELDS = [
  'name', 'description', 'enabled', 'action', 'direction', 'src_ip', 'dst_ip',
  'src_device', 'dst_device', 'app_id', 'url_category', 'content_profile',
  'src_port', 'dst_port', 'protocol', 'interface', 'schedule', 'priority', 'log_enabled',
];

/** Stable comparison fingerprint of a policy's enforcement-relevant fields. */
export function policyFingerprint(p) {
  const norm = {};
  for (const f of FIELDS) {
    let v = p[f];
    if (f === 'enabled' || f === 'log_enabled') v = v ? 1 : 0;
    norm[f] = v ?? '';
  }
  const tags = Array.isArray(p.tags) ? [...p.tags].map(String).sort() : [];
  return JSON.stringify({ ...norm, tags });
}

/**
 * Diffs candidate vs running policy arrays.
 * @returns { added, removed, modified, pending } counts.
 */
export function diffPolicies(candidate = [], running = []) {
  const cand = new Map(candidate.map(p => [p.id, policyFingerprint(p)]));
  const run = new Map(running.map(p => [p.id, policyFingerprint(p)]));

  let added = 0, removed = 0, modified = 0;
  for (const [id, fp] of cand) {
    if (!run.has(id)) added++;
    else if (run.get(id) !== fp) modified++;
  }
  for (const id of run.keys()) {
    if (!cand.has(id)) removed++;
  }
  return { added, removed, modified, pending: added + removed + modified };
}
