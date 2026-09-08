const fs = require('fs');
const assert = require('assert');

const html = fs.readFileSync('content/index.html', 'utf8');
const css = fs.readFileSync('public/assets/css/style.css', 'utf8');
const js = fs.readFileSync('public/assets/js/script.js', 'utf8');

assert(html.includes('id="network-chart"'), 'overview must expose a network activity chart');
assert(js.includes("s.network.received-lastNetworkSample.received"), 'network chart must derive a rate from cumulative receive counters');
assert(js.includes("s.network.transmitted-lastNetworkSample.transmitted"), 'network chart must derive a rate from cumulative transmit counters');
assert(css.includes('grid-template-columns:repeat(3,minmax(0,1fr))'), 'wide overview must give metric cards three balanced columns');
assert(css.includes('.monitor-layout .metric-card .metric-spark') && css.includes('height:96px'), 'metric sparklines must use a substantial part of their cards');
assert(html.includes('class="agent-compose-toolbar"'), 'standalone agent actions must use the stable toolbar grouping');
assert(css.includes('grid-template-columns:minmax(0,1fr) auto minmax(0,1fr)'), 'copy-session action must occupy a stable center track');

console.log('warden monitor and standalone agent toolbar contract: ok');
