const fs = require('fs');
const assert = require('assert');

const html = fs.readFileSync('content/index.html', 'utf8');
const css = fs.readFileSync('public/assets/css/style.css', 'utf8');
const js = fs.readFileSync('public/assets/js/script.js', 'utf8');

assert(html.includes('id="network-chart"'), 'overview must expose a network activity chart');
assert(js.includes("s.network.received-lastNetworkSample.received"), 'network chart must derive a rate from cumulative receive counters');
assert(js.includes("s.network.transmitted-lastNetworkSample.transmitted"), 'network chart must derive a rate from cumulative transmit counters');
assert(css.includes('grid-template-columns:repeat(3,minmax(0,1fr))'), 'wide overview must give metric cards three balanced columns');
assert(css.includes('.monitor-layout .metric-card .metric-spark') && css.includes('top:130px;bottom:10px') && css.includes('height:auto'), 'metric sparklines must fill the card below its text with bottom padding');
assert(css.includes('.monitor-layout .primary-metric #cpu-chart{top:112px') && css.includes('.monitor-layout .network-metric .metric-spark{top:112px'), 'CPU and network charts must leave a deliberate gap below their detail text');
assert(js.includes("drawLine($('#mem-chart'),[history.memory],['#8c9295']);drawLine($('#disk-chart'),[history.disk],['#8c9295']);"), 'memory and storage charts must be line-only without gradient fills');
assert(html.includes('class="agent-compose-toolbar"'), 'standalone agent actions must use the stable toolbar grouping');
assert(css.includes('grid-template-columns:auto minmax(0,1fr) minmax(0,1fr)'), 'copy-session action must occupy the fixed left track before provider controls');
assert(html.indexOf('id="agent-copy-session"') < html.indexOf('id="agent-provider"'), 'copy-session action must precede the model/provider selector');

console.log('warden monitor and standalone agent toolbar contract: ok');
