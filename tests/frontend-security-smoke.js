const fs = require('fs');
const vm = require('vm');

const html = fs.readFileSync('content/index.html', 'utf8');
const css = fs.readFileSync('content/assets/css/style.css', 'utf8');
const js = fs.readFileSync('content/assets/js/script.js', 'utf8');

for (const required of ['class="skip-link"', 'id="workspace-main"', 'aria-live="polite"']) {
  if (!html.includes(required)) throw new Error(`missing accessibility contract: ${required}`);
}
for (const required of [':focus-visible', 'prefers-reduced-motion:reduce']) {
  if (!css.includes(required)) throw new Error(`missing CSS accessibility contract: ${required}`);
}
for (const forbidden of ['document.write(', '.outerHTML=', 'eval(', 'new Function(']) {
  if (js.includes(forbidden)) throw new Error(`forbidden frontend sink: ${forbidden}`);
}

const start = js.indexOf('function esc(s)');
const end = js.indexOf('\n', start);
const context = {};
vm.createContext(context);
vm.runInContext(`${js.slice(start, end)};this.escapeHTML=esc`, context);
const hostile = `<img src=x onerror="globalThis.pwned=1">'&`;
const escaped = context.escapeHTML(hostile);
if (escaped.includes('<') || escaped.includes('>') || escaped.includes('"') || escaped.includes("'")) {
  throw new Error(`HTML escaper retained executable punctuation: ${escaped}`);
}
for (const token of ['&lt;', '&gt;', '&quot;', '&#39;', '&amp;']) {
  if (!escaped.includes(token)) throw new Error(`HTML escaper omitted ${token}`);
}

// cssEscape fallback must escape quotes and backslashes when CSS.escape is
// unavailable (older browsers). This guards the generated public build: the
// source uses a replacement callback without $& so the fallback survives the
// generator without losing its escaping backslash.
const cssLine = js.split('\n').find((l) => l.includes('function cssEscape'));
if (!cssLine) throw new Error('cssEscape fallback missing from script');
const cssCtx = {};
cssCtx.window = cssCtx;
cssCtx.globalThis = cssCtx;
vm.createContext(cssCtx);
vm.runInContext(cssLine, cssCtx);
if (cssCtx.window.CSS !== undefined) throw new Error('expected CSS.escape to be unavailable in sandbox');
const raw = 'a"b\\c';
const escapedAttr = vm.runInContext(`cssEscape(${JSON.stringify(raw)})`, cssCtx);
const want = 'a\\"b\\\\c';
if (escapedAttr !== want) {
  throw new Error(`cssEscape fallback failed to escape quotes/backslashes: ${JSON.stringify(escapedAttr)}`);
}
console.log('warden frontend security smoke: ok');
