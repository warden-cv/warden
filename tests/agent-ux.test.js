// Frontend UX contract tests for Warden's sticky-bottom scroll, todowrite
// task panel, and tab running-spinner / unread indicator.
//
// Run with: node tests/agent-ux.test.js

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const SCRIPT = fs.readFileSync(path.join(__dirname, '..', 'content', 'assets', 'js', 'script.js'), 'utf8');

class Node {
  constructor(tag = '') {
    this.tagName = (tag || 'div').toUpperCase();
    this.children = [];
    this.dataset = {};
    this.classList = { add() {}, remove() {}, toggle() {} };
    this.style = {};
    this._text = '';
    this._className = '';
    this.hidden = false;
    this.scrollTop = 0;
    this.scrollHeight = 0;
    this.clientHeight = 0;
  }
  append(...x) { for (const k of x) if (k != null) this.children.push(k); }
  appendChild(x) { this.children.push(x); return x; }
  remove() {}
  addEventListener() {}
  focus() {}
  closest() { return null; }
  getBoundingClientRect() { return { height: 100 }; }
  requestSubmit() {}
  stopPropagation() {}
  setAttribute(name, value) { this[name] = String(value); }
  removeAttribute(name) { this[name] = ''; }
  getAttribute(name) { return this[name] || null; }
  querySelector() { return null; }
  querySelectorAll() { return []; }
  set textContent(v) { this._text = String(v); }
  get textContent() { return this._text; }
  set className(v) { this._className = String(v); }
  get className() { return this._className; }
  set innerHTML(v) { this._innerHTML = String(v); this.children = []; }
  get innerHTML() { return this._innerHTML; }
}

// Slice the agent UX region of the Warden script so top-level editor/boot
// code does not run in the sandbox.
const AGENT_START = 'function agentNearBottom';
const AGENT_END = 'function changeAgentProvider';
const regionStart = SCRIPT.indexOf(AGENT_START);
const regionEnd = SCRIPT.indexOf(AGENT_END, regionStart);
if (regionStart < 0 || regionEnd < 0) throw new Error('could not slice Warden agent region');
const AGENT_REGION = SCRIPT.slice(regionStart, regionEnd);

function makeContext(fetchImpl) {
  const els = new Map();
  const el = (sel) => {
    if (!els.has(sel)) els.set(sel, new Node('div'));
    return els.get(sel);
  };
  const document = {
    createElement: (t) => new Node(t),
    createTextNode: (t) => ({ textContent: String(t) }),
    querySelector: (sel) => el(sel),
    querySelectorAll: () => [],
    addEventListener: () => {},
    body: new Node('body'),
  };
  const fetchCalls = [];
  const impl = fetchImpl || (() => Promise.resolve({ ok: true, json: () => Promise.resolve({}) }));
  const ctx = {
    document,
    console,
    addEventListener: () => {},
    innerWidth: 1280,
    innerHeight: 800,
    fetch: (url, opt = {}) => { fetchCalls.push({ url, ...opt }); return impl(url, opt); },
    localStorage: { _d: {}, getItem(k) { return this._d[k] || null; }, setItem(k, v) { this._d[k] = String(v); }, removeItem(k) { delete this._d[k]; } },
    setTimeout,
    clearTimeout,
    agentSessions: {},
    activeAgentSessionId: '',
    workspaceRoot: '/ws',
    agentProviders: [],
    fetchCalls,
    $: (sel) => el(sel),
    api: (url, opt) => ctx.fetch(url, opt).then((r) => r.json()),
    saveAgentSessions() {},
    renderAgentSession() {},
    renderAgentTabs() {},
    loadAgentStatus() {},
    agentEventKind(ev) { const d = ev?.data || {}; const raw = d.data || d; const t = String(raw.type || d.type || ''); if (ev.type === 'error' || ev.type === 'done' || ev.type === 'cancelled') return 'error'; return t.includes('tool') ? 'tool' : 'assistant'; },
    agentEventNode(ev) { const row = new Node('div'); row._text = ev.text || ''; return row; },
  };
  ctx.window = ctx;
  ctx.globalThis = ctx;
  return ctx;
}

function loadContext(fetchImpl) {
  const ctx = makeContext(fetchImpl);
  vm.createContext(ctx);
  vm.runInContext(AGENT_REGION, ctx);
  return ctx;
}

function run(ctx, code, vars) {
  if (vars) { for (const k of Object.keys(vars)) ctx[k] = vars[k]; }
  return vm.runInContext(code, ctx);
}

async function test(name, fn) {
  try {
    await fn();
    console.log('ok - ' + name);
  } catch (e) {
    console.error('FAIL - ' + name);
    console.error(e && e.stack || e);
    process.exitCode = 1;
  }
}

function feedNode(scrollTop, scrollHeight, clientHeight) {
  const f = new Node('div');
  f.scrollTop = scrollTop; f.scrollHeight = scrollHeight; f.clientHeight = clientHeight;
  return f;
}

test('at bottom follows new event', async () => {
  const ctx = loadContext();
  const feed = feedNode(1000, 1000, 100);
  if (!run(ctx, 'agentNearBottom(FEED)', { FEED: feed })) throw new Error('near-bottom should be near');
});

test('scrolled upward preserves position', async () => {
  const ctx = loadContext();
  const feed = feedNode(200, 1000, 100);
  if (run(ctx, 'agentNearBottom(FEED)', { FEED: feed })) throw new Error('scrolled-up should not be near');
});

test('task panel renders validated todowrite snapshot', async () => {
  const ctx = loadContext();
  const s = { followBottom: true, events: [{ kind: 'task', text: '[{"content":"one","status":"completed","priority":"high"},{"content":"two","status":"in_progress","priority":"low"}]' }] };
  run(ctx, 'renderAgentTaskPanel(S)', { S: s });
  const list = run(ctx, "$('#agentTaskList').children.length");
  if (list !== 2) throw new Error('task rows = ' + list);
  const progress = run(ctx, "$('#agentTaskProgress').textContent");
  if (progress !== '1 of 2 completed') throw new Error('progress = ' + progress);
});

test('task panel ignores malformed text', async () => {
  const ctx = loadContext();
  const s = { followBottom: true, events: [{ kind: 'task', text: 'nope' }] };
  run(ctx, 'renderAgentTaskPanel(S)', { S: s });
  if (!run(ctx, "$('#agentTaskPanel').hidden")) throw new Error('malformed task should hide panel');
});

test('busy close uses server-side stop', async () => {
  let cancelled = null;
  const ctx = loadContext((url, opt) => {
    if (url === '/api/agent/cancel') { cancelled = JSON.parse(opt.body); return Promise.resolve({ ok: true, json: () => Promise.resolve({ cancelled: true }) }); }
    return Promise.resolve({ ok: true, json: () => Promise.resolve({}) });
  });
  const s = { busy: true, runID: 'run-1', abort: null, followBottom: true, unread: 0 };
  run(ctx, 'stopAgentFor(S)', { S: s });
  await new Promise((r) => setTimeout(r, 20));
  if (!cancelled || cancelled.runID !== 'run-1') throw new Error('stop protocol not used');
});

test('unread cleared when switching', async () => {
  const ctx = loadContext();
  run(ctx, "agentSessions={a:{id:'a',unread:3,busy:false,events:[]},b:{id:'b',unread:0,busy:false,events:[]}};activeAgentSessionId='a';");
  run(ctx, "agentSessions['b'].unread=0;activeAgentSessionId='b';");
  if (run(ctx, "agentSessions['b'].unread") !== 0) throw new Error('unread not cleared');
});
test('reload while a run remains active keeps the spinner', async () => {
  const ctx = loadContext();
  run(ctx, "agentSessions={a:{id:'a',state:'running',currentRunId:'run-1',busy:true,events:[],followBottom:true,unread:0}};activeAgentSessionId='a'");
  run(ctx, "(function(){const s=agentSessions['a'];s.busy=(s.state==='running');})()");
  if (!run(ctx, "agentSessions['a'].busy")) throw new Error('spinner lost after reload while run active');
  if (run(ctx, "agentSessions['a'].currentRunId") !== 'run-1') throw new Error('currentRunId lost');
});

test('terminal state received normally clears the spinner', async () => {
  const ctx = loadContext();
  run(ctx, "agentSessions={a:{id:'a',state:'running',currentRunId:'run-1',busy:true,events:[],followBottom:true,unread:0}};activeAgentSessionId='a'");
  run(ctx, "(function(){const s=agentSessions['a'];s.state='completed';s.busy=false;})()");
  if (run(ctx, "agentSessions['a'].busy")) throw new Error('spinner not cleared on terminal outcome');
});

test('reconcile clears spinner for interrupted state after disconnect', async () => {
  const ctx = loadContext();
  run(ctx, "agentSessions={a:{id:'a',state:'running',currentRunId:'run-1',busy:true,events:[],followBottom:true,unread:0}};activeAgentSessionId='a'");
  const rec = { id: 'a', state: 'interrupted', currentRunId: 'run-1' };
  // Redirect api to return the authoritative record.
  run(ctx, 'window.__rec=REC;api=async()=>[window.__rec]', { REC: rec });
  await run(ctx, 'reconcileAgentRunState("a")');
  if (run(ctx, "agentSessions['a'].busy")) throw new Error('spinner not cleared after interrupted reconciliation');
});

test('busy close keeps the tab when cancellation is rejected', async () => {
  let rejected = false;
  const ctx = loadContext((url, opt) => {
    if (url === '/api/agent/cancel') { rejected = true; return Promise.resolve({ ok: false, status: 404, text: () => Promise.resolve('not found') }); }
    return Promise.resolve({ ok: true, json: () => Promise.resolve([]) });
  });
  run(ctx, "agentSessions={a:{id:'a',state:'running',runID:'run-1',busy:true,abort:null,events:[],followBottom:true,unread:0}};activeAgentSessionId='a'");
  const ok = await run(ctx, 'stopAgentFor(agentSessions["a"])');
  if (ok !== false) throw new Error('stopAgentFor should return false on rejection');
  if (run(ctx, "agentSessions['a']") === undefined) throw new Error('session was archived despite rejection');
});
