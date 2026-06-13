/**
 * Prometheus exposition-format rendering for HomeShield metrics.
 *
 * The server collects metric "families" from the database and renders them
 * with renderPrometheus(); the rendering is pure and unit tested in
 * metrics.test.mjs.
 */

function escapeHelp(text) {
  return String(text).replace(/\\/g, '\\\\').replace(/\n/g, '\\n');
}

function escapeLabelValue(value) {
  return String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n');
}

function formatLabels(labels) {
  const keys = Object.keys(labels || {});
  if (!keys.length) return '';
  const parts = keys.map(k => `${k}="${escapeLabelValue(labels[k])}"`);
  return `{${parts.join(',')}}`;
}

/**
 * Renders metric families into Prometheus text exposition format.
 *
 * @param families array of:
 *   { name, help, type ('gauge'|'counter'), samples: [{ value, labels? }] }
 * Samples with non-finite values are skipped.
 */
export function renderPrometheus(families) {
  const lines = [];
  for (const family of families) {
    if (!family || !family.name) continue;
    const samples = (family.samples || []).filter(s => Number.isFinite(Number(s.value)));
    if (family.help) lines.push(`# HELP ${family.name} ${escapeHelp(family.help)}`);
    if (family.type) lines.push(`# TYPE ${family.name} ${family.type}`);
    for (const sample of samples) {
      lines.push(`${family.name}${formatLabels(sample.labels)} ${Number(sample.value)}`);
    }
  }
  return lines.join('\n') + '\n';
}

/**
 * Convenience builder: turns rows of { <labelKey>, count } into samples for a
 * single family, e.g. groupSamples(rows, 'action') → [{value, labels:{action}}].
 */
export function groupSamples(rows, labelKey, valueKey = 'count') {
  return (rows || []).map(r => ({
    value: Number(r[valueKey]) || 0,
    labels: { [labelKey]: String(r[labelKey] ?? 'unknown') },
  }));
}
