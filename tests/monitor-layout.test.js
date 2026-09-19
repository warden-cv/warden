// Overview monitor-layout contract: MACHINE and NETWORK form one balanced
// 50/50 row at desktop widths, the metric spark charts resize with their cards
// (definite calc height, not intrinsic height) and keep bottom padding, the
// MACHINE card scrolls internally when its content overflows, and the
// responsive breakpoint stacks everything. Also guards the chart geometry so
// plotted lines are never clipped at the canvas top/bottom boundary.
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

// The monitor-layout grid uses six equal columns so row 1 is three equal
// thirds (CPU/MEM/STORAGE, each span 2) and row 2 is exactly 50/50
// (NETWORK span 3, MACHINE span 3).
const baseLayout = ruleFor('.monitor-layout{height:100%');
assert(baseLayout, '.monitor-layout base rule must exist');
assert(baseLayout.body.includes('repeat(6,minmax(0,1fr))'), 'monitor-layout must use six equal columns');
assert(baseLayout.body.includes('gap:12px'), 'monitor-layout must keep the normal 12px grid gap');

// NETWORK and MACHINE each span 3 of 6 columns, so the middle row is 50/50.
// Match the exact rule text because the shorter selector is a prefix of the
// longer ".monitor-layout .network-metric .metric-spark" override rule.
function exactRule(selectorText) {
  const idx = css.indexOf(selectorText + '{');
  if (idx < 0) return null;
  const brace = css.indexOf('{', idx);
  const close = css.indexOf('}', brace);
  return { selector: selectorText, body: css.slice(brace + 1, close) };
}
// exactRule finds the first match, which for the system-panel is the earlier
// responsive collapse rule; find the base rule (the one spanning 3 columns).
function ruleWith(selectorText, bodyFragment) {
  let idx = css.indexOf(selectorText + '{');
  while (idx >= 0) {
    const brace = css.indexOf('{', idx);
    const close = css.indexOf('}', brace);
    if (css.slice(brace + 1, close).includes(bodyFragment)) {
      return { selector: selectorText, body: css.slice(brace + 1, close) };
    }
    idx = css.indexOf(selectorText + '{', brace + 1);
  }
  return null;
}
const net = exactRule('.monitor-layout .network-metric');
assert(net, '.monitor-layout .network-metric must exist');
assert(net.body.includes('grid-column:span 3'), 'NETWORK must span 3 of 6 columns so it is 50% wide');
const sys = ruleWith('.monitor-layout .system-panel', 'grid-column:span 3');
assert(sys, '.monitor-layout .system-panel must exist');
assert(sys.body.includes('grid-column:span 3'), 'MACHINE must span 3 of 6 columns so it is 50% wide');
assert(!sys.body.includes('grid-column:2/4'), 'system-panel must not span 2 of 3 columns');

// CPU/MEM/STORAGE each span 2 of 6 (equal thirds).
const metric = ruleWith('.monitor-layout .metric-card', 'grid-column:span 2');
assert(metric && metric.body.includes('grid-column:span 2'), 'metric cards must span 2 of 6 columns');

// The MACHINE card scrolls internally when its content overflows.
assert(sys.body.includes('overflow-y:auto'), 'system-panel must scroll internally when content overflows');

// Metric spark charts resize with their cards: they use a definite calc height
// (not intrinsic height:auto) so they track the card as the window shrinks,
// and they keep deliberate bottom padding from the card edge.
const spark = exactRule('.monitor-layout .metric-card .metric-spark');
assert(spark, '.monitor-layout .metric-card .metric-spark must exist');
assert(spark.body.includes('bottom:16px'), 'metric spark chart must keep 16px bottom padding from the card edge');
assert(spark.body.includes('height:calc(100% - 146px)'), 'metric spark chart must use calc height so it resizes with the card');
const cpuChart = exactRule('.monitor-layout .primary-metric #cpu-chart');
assert(cpuChart && cpuChart.body.includes('bottom:16px'), 'CPU chart must keep 16px bottom padding from the card edge');
assert(cpuChart && cpuChart.body.includes('height:calc(100% - 146px)'), 'CPU chart must use calc height so it resizes with the card');
const netChart = exactRule('.monitor-layout .network-metric .metric-spark');
assert(netChart && netChart.body.includes('height:calc(100% - 146px)'), 'NETWORK chart must use calc height so it resizes with the card');

// The monitor view scrolls vertically when the layout cannot fit the window,
// so the bottom row is reachable instead of being clipped.
const viewMonitor = ruleWith('#view-monitor', 'overflow:auto');
assert(viewMonitor && viewMonitor.body.includes('overflow:auto'), 'monitor view must scroll when the grid cannot fit');

// Responsive: at max-width 900px the monitor-layout collapses to one column so
// everything stacks. Scan the whole media block (it contains nested braces).
const mediaIdx = css.indexOf('@media(max-width:900px)');
assert(mediaIdx >= 0, 'max-width:900px media block must exist');
let depth = 0, mediaEnd = -1;
for (let i = mediaIdx; i < css.length; i++) {
  if (css[i] === '{') depth++;
  else if (css[i] === '}') { depth--; if (depth === 0) { mediaEnd = i; break; } }
}
const media = css.slice(mediaIdx, mediaEnd);
assert(media.includes('.monitor-layout{grid-template-columns:1fr'), 'monitor-layout must stack at max-width 900px');
assert(media.includes('#view-monitor .monitor-layout .network-metric') && media.includes('grid-column:auto'),
  'responsive block must reset NETWORK/MACHINE spans so they stack at full width');

// Chart geometry: drawLine must inset the plot area vertically so lines at the
// minimum/maximum value are never clipped at the canvas boundary.
assert(js.includes('const padTop=4,padBottom=4'), 'drawLine must declare 4px top/bottom plot padding');
assert(js.includes('plotTop+plotH-(Math.min(100,v)/100*plotH)'), 'drawLine must map values into the padded plot area');
assert(js.includes('plotTop+plotH*y/4'), 'grid lines must draw inside the padded plot area');

console.log('warden monitor-layout contract: PASS');