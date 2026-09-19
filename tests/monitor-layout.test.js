// Overview monitor-layout contract: MACHINE and NETWORK form one balanced
// 50/50 row at desktop widths, the metric spark charts keep deliberate bottom
// padding from the card edge, and the responsive breakpoint stacks them. Also
// guards the chart geometry so plotted lines are never clipped at the canvas
// top/bottom boundary.
//
// Run with: node tests/monitor-layout.test.js

const fs = require('fs');
const assert = require('assert');

const css = fs.readFileSync('public/assets/css/style.css', 'utf8');
const js = fs.readFileSync('public/assets/js/script.js', 'utf8');

// .monitor-layout rules live on one minified line. Match the whole rule
// (selector { body }) with a regex so minification does not break parsing.
function ruleFor(selectorFragment) {
  const idx = css.indexOf(selectorFragment);
  if (idx < 0) return null;
  const brace = css.indexOf('{', idx);
  if (brace < 0) return null;
  const close = css.indexOf('}', brace);
  if (close < 0) return null;
  // The selector begins at a boundary (start, '}', or ' ') immediately before
  // the fragment so we do not match a substring inside a longer selector.
  const before = idx === 0 ? '' : css[idx - 1];
  if (before !== '' && before !== '}' && before !== ' ' && before !== '\n') return null;
  return { selector: css.slice(0, brace).trim().split(/\s*\}/).pop(), body: css.slice(brace + 1, close) };
}

// MACHINE (system-panel) and NETWORK share one row at 50/50: system-panel must
// occupy a single column (not span 2 of 3) so the row is Network + Machine.
const sys = ruleFor('.monitor-layout .system-panel');
assert(sys, '.monitor-layout .system-panel must exist');
assert(sys.body.includes('grid-column:2'), 'system-panel must occupy a single column so MACHINE is 50% beside NETWORK');
assert(!sys.body.includes('grid-column:2/4'), 'system-panel must not span 2 of 3 columns');

// The monitor-layout grid uses equal columns (three 1fr) so the machine/network
// row is exactly 50/50.
const baseLayout = ruleFor('.monitor-layout{height:100%');
assert(baseLayout, '.monitor-layout base rule must exist');
assert(baseLayout.body.includes('repeat(3,minmax(0,1fr))'), 'monitor-layout must use three equal columns');

// Metric spark charts keep deliberate bottom padding from the card edge.
const spark = ruleFor('.monitor-layout .metric-card .metric-spark');
assert(spark, '.monitor-layout .metric-card .metric-spark must exist');
assert(spark.body.includes('bottom:16px'), 'metric spark chart must keep 16px bottom padding from the card edge');
const cpuChart = ruleFor('.monitor-layout .primary-metric #cpu-chart');
assert(cpuChart && cpuChart.body.includes('bottom:16px'), 'CPU chart must keep 16px bottom padding from the card edge');

// Responsive: at max-width 900px the monitor-layout collapses to one column so
// MACHINE/NETWORK stack. Scan the whole media block (it contains nested braces).
const mediaIdx = css.indexOf('@media(max-width:900px)');
assert(mediaIdx >= 0, 'max-width:900px media block must exist');
let depth = 0, mediaEnd = -1;
for (let i = mediaIdx; i < css.length; i++) {
  if (css[i] === '{') depth++;
  else if (css[i] === '}') { depth--; if (depth === 0) { mediaEnd = i; break; } }
}
const media = css.slice(mediaIdx, mediaEnd);
assert(media.includes('.monitor-layout{grid-template-columns:1fr'), 'monitor-layout must stack at max-width 900px');

// Chart geometry: drawLine must inset the plot area vertically so lines at the
// minimum/maximum value are never clipped at the canvas boundary.
assert(js.includes('const padTop=4,padBottom=4'), 'drawLine must declare 4px top/bottom plot padding');
assert(js.includes('plotTop+plotH-(Math.min(100,v)/100*plotH)'), 'drawLine must map values into the padded plot area');
assert(js.includes('plotTop+plotH*y/4'), 'grid lines must draw inside the padded plot area');

console.log('warden monitor-layout contract: PASS');