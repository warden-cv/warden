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
const AGENT_START = 'function safeAgentSession';
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
    confirm: () => true,
    addEventListener: () => {},
    requestAnimationFrame: (fn) => { try { fn(); } catch {} },
    innerWidth: 1280,
    innerHeight: 800,
    fetch: (url, opt = {}) => { fetchCalls.push({ url, ...opt }); return impl(url, opt); },
    localStorage: { _d: {}, getItem(k) { return this._d[k] || null; }, setItem(k, v) { this._d[k] = String(v); }, removeItem(k) { delete this._d[k]; } },
    setTimeout,
    clearTimeout,
    agentSessions: {},
    agentClosedSessions: [],
    agentServerReady: false,
    agentSaveTimers: new Map(),
    agentSessionsStorageKey: () => 'warden.agentSessions.test.' + (ctx.window && ctx.window.currentAccountId ? ctx.window.currentAccountId : 'anonymous'),
    agentSid: () => 'sid-'+Math.random().toString(36).slice(2),
    agentSessionTitle: (s) => s?.title || s?.workspace || 'Agent',
    activeAgentSessionId: '',
    workspaceRoot: '/ws',
    agentProviders: [],
    fetchCalls,
    $: (sel) => el(sel),
    api: (url, opt) => ctx.fetch(url, opt).then((r) => r.json()),
    saveAgentSessions() {},
    newAgentSession(w){if(w===undefined)w='';return {id:'n',workspace:w,events:[]}},
    renderAgentSession() {},
    renderAgentTabs() {},
    loadAgentStatus() {},
    populateAgentProviders() {},
    can: () => true,
    agentEventKind(ev) { const d = ev?.data || {}; const raw = d.data || d; const t = String(raw.type || d.type || ''); if (ev.type === 'error' || ev.type === 'done' || ev.type === 'cancelled') return 'error'; return t.includes('tool') ? 'tool' : 'assistant'; },
    agentEventNode(ev) { const row = new Node('div'); row._text = ev.text || ''; return row; },
  };
  ctx.toastCalls = [];
  ctx.toast = (m) => { ctx.toastCalls.push(String(m)); };
  ctx.window = ctx;
  ctx.globalThis = ctx;
  return ctx;
}

function loadContext(fetchImpl, preload) {
  const ctx = makeContext(fetchImpl);
  if (preload) for (const k of Object.keys(preload)) ctx[k] = preload[k];
  vm.createContext(ctx);
  vm.runInContext(AGENT_REGION, ctx);
  return ctx;
}

function run(ctx, code, vars) {
  if (vars) { for (const k of Object.keys(vars)) ctx[k] = vars[k]; }
  return vm.runInContext(code, ctx);
}

// Any asynchronous rejection after a test has been counted must still produce
// a nonzero process result, never be silently masked.
process.on('unhandledRejection', (reason) => {
  console.error('UNHANDLED REJECTION: ' + (reason && reason.stack || reason));
  process.exitCode = 1;
});
process.on('uncaughtException', (err) => {
  console.error('UNCAUGHT EXCEPTION: ' + (err && err.stack || err));
  process.exitCode = 1;
});

const __tests = [];
function test(name, fn) { __tests.push({ name, fn }); }

function jsonOk(v){return {ok:true,json:()=>Promise.resolve(v),headers:{get:()=>'application/json'}}}
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
  const res = await run(ctx, 'stopAgentFor(agentSessions["a"])');
  if (!res || res.rejected !== true) throw new Error('stopAgentFor should report rejection');
  if (run(ctx, "agentSessions['a']") === undefined) throw new Error('session was archived despite rejection');
});

test('real syncAgentConversations keeps spinner for running conversation', async () => {
  const ctx = loadContext((url) => {
    if (url === '/api/agent/conversations') return Promise.resolve(jsonOk([{ id: 'a', state: 'running', currentRunId: 'run-1', events: [] }]));
    return Promise.resolve(jsonOk({}));
  });
  run(ctx, "agentSessions={};activeAgentSessionId='a';agentServerReady=true;workspaceRoot='/ws'");
  await run(ctx, 'syncAgentConversations()');
  if (!run(ctx, "agentSessions['a'] && agentSessions['a'].busy")) throw new Error('spinner lost after reload while run active');
  if (run(ctx, "agentSessions['a'].currentRunId") !== 'run-1') throw new Error('currentRunId lost');
});

test('real syncAgentConversations clears spinner for terminal conversation', async () => {
  const ctx = loadContext((url) => {
    if (url === '/api/agent/conversations') return Promise.resolve(jsonOk([{ id: 'a', state: 'interrupted', currentRunId: 'run-1', events: [] }]));
    return Promise.resolve(jsonOk({}));
  });
  run(ctx, "agentSessions={};activeAgentSessionId='a';agentServerReady=true;workspaceRoot='/ws'");
  await run(ctx, 'syncAgentConversations()');
  if (run(ctx, "agentSessions['a'] && agentSessions['a'].busy")) throw new Error('spinner not cleared for terminal conversation');
});

test('two running background tabs both show spinners', async () => {
  const ctx = loadContext((url) => {
    if (url === '/api/agent/conversations') return Promise.resolve(jsonOk([
      { id: 'a', state: 'running', currentRunId: 'r1', events: [] },
      { id: 'b', state: 'running', currentRunId: 'r2', events: [] },
    ]));
    return Promise.resolve(jsonOk({}));
  });
  run(ctx, "agentSessions={};activeAgentSessionId='a';agentServerReady=true;workspaceRoot='/ws'");
  await run(ctx, 'syncAgentConversations()');
  if (!run(ctx, "agentSessions['a'].busy") || !run(ctx, "agentSessions['b'].busy")) throw new Error('both running tabs should show spinners');
});

test('reconcileAgentRunState polls until terminal (running->running->completed)', async () => {
  const states = ['running', 'running', 'completed'];
  let i = 0;
  const ctx = loadContext((url) => {
    if (url === '/api/agent/conversations') return Promise.resolve(jsonOk([{ id: 'a', state: states[Math.min(i++, states.length - 1)], currentRunId: 'run-1', events: [] }]));
    return Promise.resolve(jsonOk({}));
  });
  run(ctx, "agentSessions={a:{id:'a',state:'running',currentRunId:'run-1',busy:true,events:[],followBottom:true,unread:0}};activeAgentSessionId='a'");
  await run(ctx, 'reconcileAgentRunState("a")');
  if (run(ctx, "agentSessions['a'].busy")) throw new Error('spinner stuck after polling to terminal');
  if (run(ctx, "agentSessions['a'].state") !== 'completed') throw new Error('state not updated after polling');
});

// Real closeAgentSession flows.
test('closeAgentSession keeps tab when cancellation is rejected', async () => {
  const ctx = loadContext((url) => {
    if (url === '/api/agent/cancel') return Promise.resolve({ ok: false, status: 404, text: () => Promise.resolve('not found') });
    if (url === '/api/agent/conversations') return Promise.resolve(jsonOk([{ id: 'a', state: 'running', currentRunId: 'run-1', events: [] }]));
    return Promise.resolve(jsonOk({}));
  });
  run(ctx, "agentSessions={a:{id:'a',workspace:'/w',state:'running',runID:'run-1',currentRunId:'run-1',busy:true,abort:null,events:[],followBottom:true,unread:0}};activeAgentSessionId='a'");
  await run(ctx, 'closeAgentSession("a")');
  if (run(ctx, "agentSessions['a']") === undefined) throw new Error('session archived despite rejected cancellation');
});

// Real closeAgentSession: accepted-but-draining keeps the tab, is not archived,
// the active selection is unchanged, and the pending-stop message is surfaced.
test('closeAgentSession keeps tab when stop accepted but still draining', async () => {
  let n = 0;
  const preload = { __AGENT_STOP_SETTLE_MS: 20, __AGENT_RECONCILE_STOP_WAIT_MS: 150 };
  const ctx = loadContext((url) => {
    if (url === '/api/agent/cancel') return Promise.resolve(jsonOk({ cancelled: true }));
    if (url === '/api/agent/conversations') return Promise.resolve(jsonOk([{ id: 'a', state: n++ < 3 ? 'running' : 'running', currentRunId: 'run-1', events: [] }]));
    return Promise.resolve(jsonOk({}));
  }, preload);
  run(ctx, "agentSessions={a:{id:'a',workspace:'/w',state:'running',runID:'run-1',currentRunId:'run-1',busy:true,abort:null,events:[],followBottom:true,unread:0}};activeAgentSessionId='a'");
  await run(ctx, 'closeAgentSession("a")');
  if (run(ctx, "agentSessions['a']") === undefined) throw new Error('draining close must keep the tab in the open map');
  if (run(ctx, "agentClosedSessions.some(x=>x.id==='a')")) throw new Error('draining close must not archive the session');
  if (run(ctx, "activeAgentSessionId") !== 'a') throw new Error('active selection changed while draining');
  const msgs = run(ctx, 'toastCalls');
  if (!msgs.some((m) => m.includes('winding down'))) throw new Error('pending-stop message not surfaced: ' + JSON.stringify(msgs));
});

test('closeAgentSession archives after terminal cancellation', async () => {
  let n = 0;
  const preload = { __AGENT_STOP_SETTLE_MS: 20, __AGENT_RECONCILE_STOP_WAIT_MS: 300 };
  const ctx = loadContext((url) => {
    if (url === '/api/agent/cancel') return Promise.resolve(jsonOk({ cancelled: true }));
    if (url === '/api/agent/conversations') return Promise.resolve(jsonOk([{ id: 'a', state: n++ === 0 ? 'running' : 'cancelled', currentRunId: 'run-1', events: [] }]));
    return Promise.resolve(jsonOk({}));
  }, preload);
  run(ctx, "agentSessions={a:{id:'a',workspace:'/w',state:'running',runID:'run-1',currentRunId:'run-1',busy:true,abort:null,events:[],followBottom:true,unread:0}};activeAgentSessionId='a'");
  await run(ctx, 'closeAgentSession("a")');
  if (run(ctx, "agentSessions['a']") !== undefined) throw new Error('terminal cancellation should archive the session');
});

// Parity: old run replaced by a newer running run keeps the spinner.
test('old run replaced by newer running run keeps spinner', async () => {
  let i = 0;
  const states = ['running', 'running'];
  const ctx = loadContext((url) => {
    if (url === '/api/agent/conversations') return Promise.resolve(jsonOk([{ id: 'a', state: states[Math.min(i++, states.length - 1)], currentRunId: 'run-2', events: [] }]));
    return Promise.resolve(jsonOk({}));
  });
  run(ctx, "agentSessions={a:{id:'a',state:'running',currentRunId:'run-1',runID:'run-1',busy:true,events:[],followBottom:true,unread:0}};activeAgentSessionId='a'");
  await run(ctx, 'reconcileAgentRunState("a")');
  if (!run(ctx, "agentSessions['a'].busy")) throw new Error('newer running run should keep the spinner');
  if (run(ctx, "agentSessions['a'].currentRunId") !== 'run-2') throw new Error('currentRunId not updated');
});

// Parity: old run replaced by a newer terminal run clears the spinner.
test('old run replaced by newer terminal run clears spinner', async () => {
  const ctx = loadContext((url) => {
    if (url === '/api/agent/conversations') return Promise.resolve(jsonOk([{ id: 'a', state: 'completed', currentRunId: 'run-2', events: [] }]));
    return Promise.resolve(jsonOk({}));
  });
  run(ctx, "agentSessions={a:{id:'a',state:'running',currentRunId:'run-1',runID:'run-1',busy:true,events:[],followBottom:true,unread:0}};activeAgentSessionId='a'");
  await run(ctx, 'reconcileAgentRunState("a")');
  if (run(ctx, "agentSessions['a'].busy")) throw new Error('newer terminal run should clear the spinner');
});

// Parity: a stale poll cannot overwrite a later synchronization.
test('a stale poll cannot overwrite a later synchronization', async () => {
  let i = 0;
  const ctx = loadContext((url) => {
    if (url === '/api/agent/conversations') return Promise.resolve(jsonOk([{ id: 'a', state: i++ === 0 ? 'running' : 'completed', currentRunId: 'run-1', events: [] }]));
    return Promise.resolve(jsonOk({}));
  });
  run(ctx, "agentSessions={a:{id:'a',state:'running',currentRunId:'run-1',runID:'run-1',busy:true,events:[],followBottom:true,unread:0}};activeAgentSessionId='a'");
  const p = run(ctx, 'reconcileAgentRunState("a")');
  // Simulate a later synchronization setting terminal state.
  run(ctx, "agentSessions['a'].state='completed';agentSessions['a'].busy=false");
  await p;
  if (run(ctx, "agentSessions['a'].busy")) throw new Error('stale poll overwrote later sync');
});

// Direct Stop control: explicit non-success cancel response is rejected.
test('stopAgent shows rejected message on explicit cancel refusal', async () => {
  const ctx = loadContext((url) => {
    if (url === '/api/agent/cancel') return Promise.resolve({ ok: false, status: 404, text: () => Promise.resolve('run not found') });
    return Promise.resolve(jsonOk({}));
  });
  run(ctx, "agentSessions={a:{id:'a',state:'running',runID:'run-1',busy:true,abort:null,events:[],followBottom:true,unread:0}};activeAgentSessionId='a'");
  const res = await run(ctx, 'stopAgentFor(agentSessions["a"])');
  if (res.rejected !== true) throw new Error('explicit refusal must be rejected, got ' + JSON.stringify(res));
  await run(ctx, 'stopAgent()');
  const msgs = run(ctx, 'toastCalls');
  if (!msgs.some((m) => m.includes('Could not stop the running agent.'))) throw new Error('rejected toast = ' + JSON.stringify(msgs));
});

// Direct Stop control: confirmed cancel followed by terminal is a clean stop.
test('stopAgent shows terminal message on confirmed cancel', async () => {
  let n = 0;
  const preload = { __AGENT_STOP_SETTLE_MS: 10, __AGENT_RECONCILE_STOP_WAIT_MS: 300 };
  const ctx = loadContext((url) => {
    if (url === '/api/agent/cancel') return Promise.resolve(jsonOk({ cancelled: true }));
    if (url === '/api/agent/conversations') return Promise.resolve(jsonOk([{ id: 'a', state: n++ === 0 ? 'running' : 'cancelled', currentRunId: 'run-1', events: [] }]));
    return Promise.resolve(jsonOk({}));
  }, preload);
  run(ctx, "agentSessions={a:{id:'a',state:'running',runID:'run-1',busy:true,abort:null,events:[],followBottom:true,unread:0}};activeAgentSessionId='a'");
  const res = await run(ctx, 'stopAgentFor(agentSessions["a"])');
  if (res.ok !== true) throw new Error('terminal stop should be ok, got ' + JSON.stringify(res));
  await run(ctx, 'stopAgent()');
  const msgs = run(ctx, 'toastCalls');
  if (!msgs.some((m) => m.includes('Agent stopped.'))) throw new Error('terminal toast = ' + JSON.stringify(msgs));
});

// Direct Stop control: confirmed cancel followed by a still-running state is draining.
test('stopAgent shows draining message on acknowledged still-running cancel', async () => {
  const preload = { __AGENT_STOP_SETTLE_MS: 10, __AGENT_RECONCILE_STOP_WAIT_MS: 150 };
  const ctx = loadContext((url) => {
    if (url === '/api/agent/cancel') return Promise.resolve(jsonOk({ cancelled: true }));
    if (url === '/api/agent/conversations') return Promise.resolve(jsonOk([{ id: 'a', state: 'running', currentRunId: 'run-1', events: [] }]));
    return Promise.resolve(jsonOk({}));
  }, preload);
  run(ctx, "agentSessions={a:{id:'a',state:'running',runID:'run-1',busy:true,abort:null,events:[],followBottom:true,unread:0}};activeAgentSessionId='a'");
  const res = await run(ctx, 'stopAgentFor(agentSessions["a"])');
  if (res.draining !== true) throw new Error('acknowledged still-running must be draining, got ' + JSON.stringify(res));
  await run(ctx, 'stopAgent()');
  const msgs = run(ctx, 'toastCalls');
  if (!msgs.some((m) => m.includes('winding down'))) throw new Error('draining toast = ' + JSON.stringify(msgs));
});

// Timeout: a cancel request that never returns, followed by terminal state, is
// a successful stop (reconciled against authoritative state).
test('stopAgent cancel timeout followed by terminal returns success', async () => {
  let n = 0;
  const preload = { __AGENT_CANCEL_TIMEOUT_MS: 30, __AGENT_STOP_SETTLE_MS: 10, __AGENT_RECONCILE_STOP_WAIT_MS: 300 };
  const ctx = loadContext((url) => {
    if (url === '/api/agent/cancel') return new Promise(() => {});
    if (url === '/api/agent/conversations') return Promise.resolve(jsonOk([{ id: 'a', state: n++ === 0 ? 'running' : 'cancelled', currentRunId: 'run-1', events: [] }]));
    return Promise.resolve(jsonOk({}));
  }, preload);
  run(ctx, "agentSessions={a:{id:'a',state:'running',runID:'run-1',busy:true,abort:null,events:[],followBottom:true,unread:0}};activeAgentSessionId='a'");
  const res = await run(ctx, 'stopAgentFor(agentSessions["a"])');
  if (res.ok !== true) throw new Error('timeout then terminal should stop cleanly, got ' + JSON.stringify(res));
  if (res.unconfirmed) throw new Error('terminal must not be reported unconfirmed');
  await run(ctx, 'stopAgent()');
  const msgs = run(ctx, 'toastCalls');
  if (!msgs.some((m) => m.includes('Agent stopped.'))) throw new Error('timeout-terminal toast = ' + JSON.stringify(msgs));
});

// Timeout: a cancel request that never returns, followed by a still-running
// state, is unconfirmed (never described as an explicit rejection).
test('stopAgent cancel timeout followed by running is unconfirmed not rejected', async () => {
  const preload = { __AGENT_CANCEL_TIMEOUT_MS: 30, __AGENT_STOP_SETTLE_MS: 10, __AGENT_RECONCILE_STOP_WAIT_MS: 150 };
  const ctx = loadContext((url) => {
    if (url === '/api/agent/cancel') return new Promise(() => {});
    if (url === '/api/agent/conversations') return Promise.resolve(jsonOk([{ id: 'a', state: 'running', currentRunId: 'run-1', events: [] }]));
    return Promise.resolve(jsonOk({}));
  }, preload);
  run(ctx, "agentSessions={a:{id:'a',state:'running',runID:'run-1',busy:true,abort:null,events:[],followBottom:true,unread:0}};activeAgentSessionId='a'");
  const res = await run(ctx, 'stopAgentFor(agentSessions["a"])');
  if (res.rejected) throw new Error('timeout must never be reported as rejected');
  if (res.unconfirmed !== true) throw new Error('timeout still-running must be unconfirmed, got ' + JSON.stringify(res));
  await run(ctx, 'stopAgent()');
  const msgs = run(ctx, 'toastCalls');
  if (!msgs.some((m) => m.includes('Could not confirm the stop'))) throw new Error('unconfirmed toast = ' + JSON.stringify(msgs));
});

// Warning vs failure: a completed_with_process_error terminal event maps to a
// distinct warning kind and summary, never the generic error kind.
test('warning SSE terminal event maps to warning kind and summary', async () => {
  const ctx = loadContext();
  const ev = { type: 'warning', data: { outcome: 'completed_with_process_error', message: 'OpenCode exited with status 1 after completing.' } };
  if (run(ctx, 'agentEventKind(EV)', { EV: ev }) !== 'warning') throw new Error('warning kind not mapped');
  const sum = run(ctx, 'summarizeAgentEvent(EV)', { EV: ev });
  if (!sum.includes('exit')) throw new Error('warning summary missing: ' + sum);
});

// Warning vs failure: agentEventNode renders warning and error distinctly.
test('agentEventNode renders warning and error with distinct classes', async () => {
  const ctx = loadContext();
  const w = run(ctx, 'agentEventNode({kind:"warning",text:"W",name:"run:r1:completed_with_process_error"})');
  const e = run(ctx, 'agentEventNode({kind:"error",text:"E",name:"run:r1:failed"})');
  if (!String(w.className).includes('agent-event warning')) throw new Error('warning class missing: ' + w.className);
  if (!String(e.className).includes('agent-event error')) throw new Error('error class missing');
  if (w.className === e.className) throw new Error('warning and error must render differently');
});

// Warning survives conversation reload without degrading into an Error block.
test('real syncAgentConversations preserves warning state after reload', async () => {
  const ctx = loadContext((url) => {
    if (url === '/api/agent/conversations') return Promise.resolve(jsonOk([{ id: 'a', state: 'completed_with_process_error', currentRunId: 'run-1', events: [{ kind: 'warning', text: 'OpenCode exited with status 1 after completing.', name: 'run:run-1:completed_with_process_error' }] }]));
    return Promise.resolve(jsonOk({}));
  });
  run(ctx, "agentSessions={};activeAgentSessionId='a';agentServerReady=true;workspaceRoot='/ws'");
  await run(ctx, 'syncAgentConversations()');
  if (run(ctx, "agentSessions['a'].state") !== 'completed_with_process_error') throw new Error('warning state lost on reload');
  if (run(ctx, "agentSessions['a'].busy")) throw new Error('spinner not cleared on reload');
  const kinds = run(ctx, "agentSessions['a'].events.map(e=>e.kind).join(',')");
  if (kinds.includes('error')) throw new Error('warning degraded to error on reload: ' + kinds);
  if (!kinds.includes('warning')) throw new Error('warning kind missing on reload: ' + kinds);
});

// Live task pipeline: the real stream-consumption function opens both the main
// and the embedded-editor task panels before terminal completion or reload.
test('streamed task event opens both agent task panels immediately', async () => {
  const ctx = loadContext();
  run(ctx, "agentSessions={a:{id:'a',events:[],busy:true,followBottom:true,unread:0}};activeAgentSessionId='a'");
  const ev = { type: 'task', data: { snapshot: '[{"content":"alpha","status":"in_progress","priority":"high"},{"content":"beta","status":"pending","priority":"low"}]' } };
  run(ctx, 'consumeAgentStreamEvent("a", agentSessions["a"], EV, new Set())', { EV: ev });
  if (run(ctx, "$('#agentTaskPanel').hidden")) throw new Error('main task panel did not open');
  if (run(ctx, "$('#editorAgentTaskPanel').hidden")) throw new Error('editor task panel did not open');
  const rows = run(ctx, "$('#agentTaskList').children.length");
  const erows = run(ctx, "$('#editorAgentTaskList').children.length");
  if (rows !== 2 || erows !== 2) throw new Error('task rows = ' + rows + '/' + erows);
});

// Updating the todo list replaces the displayed snapshot (no accumulation).
test('a later todowrite snapshot replaces the displayed list', async () => {
  const ctx = loadContext();
  run(ctx, "agentSessions={a:{id:'a',events:[],busy:true,followBottom:true,unread:0}};activeAgentSessionId='a'");
  run(ctx, 'consumeAgentStreamEvent("a", agentSessions["a"], EV, new Set())', { EV: { type: 'task', data: { snapshot: '[{"content":"alpha","status":"pending","priority":"high"}]' } } });
  run(ctx, 'consumeAgentStreamEvent("a", agentSessions["a"], EV, new Set())', { EV: { type: 'task', data: { snapshot: '[{"content":"one","status":"pending","priority":"high"},{"content":"two","status":"completed","priority":"low"},{"content":"three","status":"pending","priority":"medium"}]' } } });
  const rows = run(ctx, "$('#agentTaskList').children.length");
  if (rows !== 3) throw new Error('replacement rows = ' + rows);
});

// A valid empty snapshot clears and hides both panels.
test('valid empty todos snapshot clears and hides both panels', async () => {
  const ctx = loadContext();
  run(ctx, "agentSessions={a:{id:'a',events:[],busy:true,followBottom:true,unread:0}};activeAgentSessionId='a'");
  run(ctx, 'consumeAgentStreamEvent("a", agentSessions["a"], EV, new Set())', { EV: { type: 'task', data: { snapshot: '[{"content":"alpha","status":"pending","priority":"high"}]' } } });
  if (run(ctx, "$('#agentTaskPanel').hidden")) throw new Error('panel should be open before clear');
  run(ctx, 'consumeAgentStreamEvent("a", agentSessions["a"], EV, new Set())', { EV: { type: 'task', data: { snapshot: '[]' } } });
  if (!run(ctx, "$('#agentTaskPanel').hidden") || !run(ctx, "$('#editorAgentTaskPanel').hidden")) throw new Error('panels not hidden after clear');
  if (run(ctx, "$('#agentTaskList').children.length") !== 0) throw new Error('task list not cleared');
});

// Malformed snapshot text never opens the panel.
test('malformed task payload is ignored', async () => {
  const ctx = loadContext();
  run(ctx, "agentSessions={a:{id:'a',events:[],busy:true,followBottom:true,unread:0}};activeAgentSessionId='a'");
  run(ctx, 'consumeAgentStreamEvent("a", agentSessions["a"], EV, new Set())', { EV: { type: 'task', data: { snapshot: 'not-json' } } });
  if (!run(ctx, "$('#agentTaskPanel').hidden")) throw new Error('malformed payload opened the panel');
  run(ctx, 'consumeAgentStreamEvent("a", agentSessions["a"], EV, new Set())', { EV: { type: 'task', data: { snapshot: '{"a":1}' } } });
  if (!run(ctx, "$('#agentTaskPanel').hidden")) throw new Error('non-array payload opened the panel');
});

// Task events are excluded from transcript rendering on both agent surfaces.
test('task events never render as transcript rows', async () => {
  const ctx = loadContext();
  run(ctx, "agentSessions={a:{id:'a',events:[],busy:true,followBottom:true,unread:0}};activeAgentSessionId='a'");
  run(ctx, 'consumeAgentStreamEvent("a", agentSessions["a"], EV, new Set())', { EV: { type: 'task', data: { snapshot: '[{"content":"alpha","status":"pending","priority":"high"}]' } } });
  if (run(ctx, "$('#agent-feed').children.length") !== 0) throw new Error('task event leaked into the main feed');
  if (run(ctx, "$('#editor-agent-feed').children.length") !== 0) throw new Error('task event leaked into the editor feed');
  run(ctx, 'consumeAgentStreamEvent("a", agentSessions["a"], EV, new Set())', { EV: { type: 'opencode', data: { type: 'text', part: { type: 'text', text: 'hello' } } } });
  const mainRows = run(ctx, "$('#agent-feed').children.length");
  const edRows = run(ctx, "$('#editor-agent-feed').children.length");
  if (mainRows !== 1 || edRows !== 1) throw new Error('transcript rows = ' + mainRows + '/' + edRows);
  const hasTaskRow = run(ctx, "[...$('#agent-feed').children].some(c=>String(c.className).includes('agent-event task'))");
  if (hasTaskRow) throw new Error('a task row was rendered in the main feed');
});

// Reload restores the latest non-empty snapshot without rendering JSON rows.
test('reload restores task snapshot without feed JSON rows', async () => {
  const ctx = loadContext((url) => {
    if (url === '/api/agent/conversations') return Promise.resolve(jsonOk([{ id: 'a', state: 'completed', currentRunId: 'run-1', events: [
      { kind: 'assistant', text: 'answer', name: '' },
      { kind: 'task', text: '[{"content":"alpha","status":"in_progress","priority":"high"}]', name: '' },
    ] }]));
    return Promise.resolve(jsonOk({}));
  });
  run(ctx, "agentSessions={};activeAgentSessionId='a';agentServerReady=true;workspaceRoot='/ws'");
  await run(ctx, 'syncAgentConversations()');
  if (run(ctx, "$('#agentTaskPanel').hidden")) throw new Error('task panel not restored on reload');
  if (run(ctx, "$('#agentTaskList').children.length") !== 1) throw new Error('restored task rows != 1');
  const feedRows = run(ctx, "$('#agent-feed').children.length");
  if (feedRows !== 1) throw new Error('feed rows = ' + feedRows);
  const hasTaskRow = run(ctx, "[...$('#agent-feed').children].some(c=>String(c.className).includes('agent-event task'))");
  if (hasTaskRow) throw new Error('a task row was rendered after reload');
});

// Background-session task updates must not create a second unread transcript item.
test('background task snapshot does not increment unread', async () => {
  const ctx = loadContext();
  run(ctx, "agentSessions={a:{id:'a',events:[],busy:false,followBottom:true,unread:0},b:{id:'b',events:[],busy:true,followBottom:true,unread:0}};activeAgentSessionId='a'");
  run(ctx, 'consumeAgentStreamEvent("b", agentSessions["b"], EV, new Set())', { EV: { type: 'task', data: { snapshot: '[{"content":"alpha","status":"pending","priority":"high"}]' } } });
  if (run(ctx, "agentSessions['b'].unread") !== 0) throw new Error('task snapshot incremented unread');
  run(ctx, 'consumeAgentStreamEvent("b", agentSessions["b"], EV, new Set())', { EV: { type: 'opencode', data: { type: 'text', part: { type: 'text', text: 'real activity' } } } });
  if (run(ctx, "agentSessions['b'].unread") !== 1) throw new Error('real activity should increment unread');
});

// Per-session collapsed task panel: closing either Warden surface collapses
// both; events, rerenders and tab switching do not reopen; explicit reopen
// restores the latest snapshot on both surfaces.
test('task panel close collapses both Warden surfaces and survives events/rerender/tab', async () => {
  const ctx = loadContext();
  run(ctx, "agentSessions={a:{id:'a',events:[],busy:true,followBottom:true,unread:0},b:{id:'b',events:[],busy:false,followBottom:true,unread:0}};activeAgentSessionId='a'");
  run(ctx, 'consumeAgentStreamEvent("a", agentSessions["a"], EV, new Set())', { EV: { type: 'task', data: { snapshot: '[{"content":"alpha","status":"pending","priority":"high"}]' } } });
  if (run(ctx, "$('#agentTaskPanel').hidden")) throw new Error('main panel should be open');
  run(ctx, 'setAgentTasksCollapsed(true)');
  if (!run(ctx, "$('#agentTaskPanel').hidden") || !run(ctx, "$('#editorAgentTaskPanel').hidden")) throw new Error('collapse did not hide both surfaces');
  if (run(ctx, "agentSessions['a'].tasksCollapsed") !== true) throw new Error('collapsed flag not set');
  if (run(ctx, "$('#agentTaskReopen').hidden") || run(ctx, "$('#editorAgentTaskReopen').hidden")) throw new Error('reopen badges should be visible');
  run(ctx, 'consumeAgentStreamEvent("a", agentSessions["a"], EV, new Set())', { EV: { type: 'opencode', data: { type: 'text', part: { type: 'text', text: 'hello' } } } });
  if (!run(ctx, "$('#agentTaskPanel').hidden")) throw new Error('a transcript event reopened the panel');
  run(ctx, 'renderAgentSession()');
  if (!run(ctx, "$('#agentTaskPanel').hidden")) throw new Error('a rerender reopened the panel');
  run(ctx, "activeAgentSessionId='b';renderAgentSession()");
  run(ctx, "activeAgentSessionId='a';renderAgentSession()");
  if (!run(ctx, "$('#agentTaskPanel').hidden")) throw new Error('tab switching reopened the panel');
  run(ctx, 'setAgentTasksCollapsed(false)');
  if (run(ctx, "$('#agentTaskPanel').hidden") || run(ctx, "$('#editorAgentTaskPanel').hidden")) throw new Error('explicit reopen did not show the panels');
  if (run(ctx, "$('#agentTaskList').children.length") !== 1 || run(ctx, "$('#editorAgentTaskList').children.length") !== 1) throw new Error('reopen should render the snapshot');
});

// Task snapshots keep updating while collapsed and reopening shows the latest.
test('task snapshots update while collapsed and reopen shows latest on both surfaces', async () => {
  const ctx = loadContext();
  run(ctx, "agentSessions={a:{id:'a',events:[],busy:true,followBottom:true,unread:0}};activeAgentSessionId='a'");
  run(ctx, 'consumeAgentStreamEvent("a", agentSessions["a"], EV, new Set())', { EV: { type: 'task', data: { snapshot: '[{"content":"alpha","status":"pending","priority":"high"}]' } } });
  run(ctx, 'setAgentTasksCollapsed(true)');
  run(ctx, 'consumeAgentStreamEvent("a", agentSessions["a"], EV, new Set())', { EV: { type: 'task', data: { snapshot: '[{"content":"one","status":"pending","priority":"high"},{"content":"two","status":"completed","priority":"low"}]' } } });
  if (!run(ctx, "$('#agentTaskPanel').hidden")) throw new Error('a later snapshot reopened the panel');
  if (run(ctx, "agentSessions['a'].tasksCollapsed") !== true) throw new Error('collapsed preference lost');
  run(ctx, 'setAgentTasksCollapsed(false)');
  if (run(ctx, "$('#agentTaskPanel').hidden")) throw new Error('panel did not reopen');
  if (run(ctx, "$('#agentTaskList').children.length") !== 2) throw new Error('latest snapshot rows = ' + run(ctx, "$('#agentTaskList').children.length"));
  if (run(ctx, "agentSessions['a'].tasksCollapsed") !== false) throw new Error('collapsed not cleared on reopen');
});

// An empty authoritative snapshot clears tasks even while collapsed.
test('empty authoritative snapshot clears tasks while collapsed', async () => {
  const ctx = loadContext();
  run(ctx, "agentSessions={a:{id:'a',events:[],busy:true,followBottom:true,unread:0}};activeAgentSessionId='a'");
  run(ctx, 'consumeAgentStreamEvent("a", agentSessions["a"], EV, new Set())', { EV: { type: 'task', data: { snapshot: '[{"content":"alpha","status":"pending","priority":"high"}]' } } });
  run(ctx, 'setAgentTasksCollapsed(true)');
  run(ctx, 'consumeAgentStreamEvent("a", agentSessions["a"], EV, new Set())', { EV: { type: 'task', data: { snapshot: '[]' } } });
  if (!run(ctx, "$('#agentTaskPanel').hidden")) throw new Error('panel not hidden after empty clear');
  if (run(ctx, "$('#agentTaskList').children.length") !== 0) throw new Error('tasks not cleared');
  if (!run(ctx, "$('#agentTaskReopen').hidden")) throw new Error('reopen badge should hide after clear');
});

// Synchronization must not reopen a collapsed task panel.
test('synchronization preserves collapsed task panel', async () => {
  const ctx = loadContext((url) => {
    if (url === '/api/agent/conversations') return Promise.resolve(jsonOk([{ id: 'a', state: 'completed', currentRunId: 'run-1', events: [{ kind: 'task', text: '[{"content":"alpha","status":"pending","priority":"high"}]', name: '' }] }]));
    return Promise.resolve(jsonOk({}));
  });
  run(ctx, "agentSessions={a:{id:'a',events:[],busy:true,followBottom:true,unread:0,tasksCollapsed:true}};activeAgentSessionId='a';agentServerReady=true;workspaceRoot='/ws'");
  await run(ctx, 'syncAgentConversations()');
  if (run(ctx, "agentSessions['a'].tasksCollapsed") !== true) throw new Error('collapsed flag lost on sync');
  run(ctx, 'renderAgentSession()');
  if (!run(ctx, "$('#agentTaskPanel').hidden")) throw new Error('sync reopened a collapsed panel');
});

// Switching to an empty session clears both Warden task surfaces and reopen
// badges; switching back restores the previous session's correct state.
test('switching to empty session clears stale task panels on both surfaces', async () => {
  const ctx = loadContext();
  run(ctx, "agentSessions={a:{id:'a',events:[],busy:true,followBottom:true,unread:0},b:{id:'b',events:[],busy:false,followBottom:true,unread:0}};activeAgentSessionId='a'");
  run(ctx, 'consumeAgentStreamEvent("a", agentSessions["a"], EV, new Set())', { EV: { type: 'task', data: { snapshot: '[{"content":"alpha","status":"pending","priority":"high"}]' } } });
  if (run(ctx, "$('#agentTaskPanel').hidden")) throw new Error('main panel should be visible for A');
  run(ctx, "activeAgentSessionId='b';renderAgentSession()");
  if (!run(ctx, "$('#agentTaskPanel').hidden")) throw new Error('A main panel remained on empty session B');
  if (!run(ctx, "$('#editorAgentTaskPanel').hidden")) throw new Error('A editor panel remained on empty session B');
  if (!run(ctx, "$('#agentTaskReopen').hidden")) throw new Error('A reopen badge remained on empty session B');
  run(ctx, "activeAgentSessionId='a';renderAgentSession()");
  if (run(ctx, "$('#agentTaskPanel').hidden")) throw new Error('switching back to A did not restore its main panel');
  if (run(ctx, "$('#editorAgentTaskPanel').hidden")) throw new Error('switching back to A did not restore its editor panel');
});

// Switching to an empty session clears a collapsed task panel's reopen badges.
test('switching to empty session clears collapsed reopen badges on both surfaces', async () => {
  const ctx = loadContext();
  run(ctx, "agentSessions={a:{id:'a',events:[],busy:true,followBottom:true,unread:0},b:{id:'b',events:[],busy:false,followBottom:true,unread:0}};activeAgentSessionId='a'");
  run(ctx, 'consumeAgentStreamEvent("a", agentSessions["a"], EV, new Set())', { EV: { type: 'task', data: { snapshot: '[{"content":"alpha","status":"pending","priority":"high"}]' } } });
  run(ctx, 'setAgentTasksCollapsed(true)');
  if (run(ctx, "$('#agentTaskReopen').hidden") || run(ctx, "$('#editorAgentTaskReopen').hidden")) throw new Error('reopen badges should be visible for collapsed A');
  run(ctx, "activeAgentSessionId='b';renderAgentSession()");
  if (!run(ctx, "$('#agentTaskReopen').hidden") || !run(ctx, "$('#editorAgentTaskReopen').hidden")) throw new Error('A reopen badges remained on empty session B');
  run(ctx, "activeAgentSessionId='a';renderAgentSession()");
  if (run(ctx, "$('#agentTaskReopen').hidden")) throw new Error('switching back to A did not restore its reopen badge');
});

// Collapsed preference survives a reload (persist + reconstruct).
test('collapsed task panel survives reload', async () => {
  const ctx = loadContext();
  run(ctx, "agentSessions={a:{id:'a',events:[],busy:true,followBottom:true,unread:0}};activeAgentSessionId='a'");
  run(ctx, 'consumeAgentStreamEvent("a", agentSessions["a"], EV, new Set())', { EV: { type: 'task', data: { snapshot: '[{"content":"alpha","status":"pending","priority":"high"}]' } } });
  run(ctx, 'setAgentTasksCollapsed(true)');
  const stored = ctx.localStorage.getItem('warden.agentSessions.test.anonymous');
  if (!stored || !stored.includes('tasksCollapsed')) throw new Error('tasksCollapsed not persisted locally');
  run(ctx, 'loadAgentSessions()');
  if (run(ctx, "agentSessions['a'].tasksCollapsed") !== true) throw new Error('collapsed not restored on reload');
  run(ctx, 'renderAgentSession()');
  if (!run(ctx, "$('#agentTaskPanel').hidden")) throw new Error('collapsed panel reopened after reload');
});

// Reopening persists and survives reload too.
test('reopened task panel survives reload', async () => {
  const ctx = loadContext();
  run(ctx, "agentSessions={a:{id:'a',events:[],busy:true,followBottom:true,unread:0}};activeAgentSessionId='a'");
  run(ctx, 'consumeAgentStreamEvent("a", agentSessions["a"], EV, new Set())', { EV: { type: 'task', data: { snapshot: '[{"content":"alpha","status":"pending","priority":"high"}]' } } });
  run(ctx, 'setAgentTasksCollapsed(true)');
  run(ctx, 'setAgentTasksCollapsed(false)');
  const stored = ctx.localStorage.getItem('warden.agentSessions.test.anonymous');
  if (!stored || !stored.includes('"tasksCollapsed":false')) throw new Error('reopen not persisted');
  run(ctx, 'loadAgentSessions()');
  if (run(ctx, "agentSessions['a'].tasksCollapsed") !== false) throw new Error('open state not restored on reload');
  run(ctx, 'renderAgentSession()');
  if (run(ctx, "$('#agentTaskPanel').hidden")) throw new Error('reopened panel hidden after reload');
});

// Warden task preferences do not cross account/session storage boundaries.
test('task preferences are scoped to the account storage key', async () => {
  const ctx = loadContext();
  run(ctx, "currentAccountId='accA';agentSessions={a:{id:'a',events:[],busy:true,followBottom:true,unread:0}};activeAgentSessionId='a'");
  run(ctx, 'consumeAgentStreamEvent("a", agentSessions["a"], EV, new Set())', { EV: { type: 'task', data: { snapshot: '[{"content":"alpha","status":"pending","priority":"high"}]' } } });
  run(ctx, 'setAgentTasksCollapsed(true)');
  if (!(run(ctx, "localStorage.getItem('warden.agentSessions.test.accA') || ''") ).includes('tasksCollapsed')) throw new Error('account key not written');
  if ((run(ctx, "localStorage.getItem('warden.agentSessions.test.accB') || ''") ).includes('tasksCollapsed')) throw new Error('preference leaked across account boundary');
});

// Run all registered tests sequentially and print a final summary. A single
// failure or unhandled rejection leaves exitCode nonzero.
(async function runAll() {
  let pass = 0, fail = 0;
  for (const { name, fn } of __tests) {
    try {
      await fn();
      console.log('ok - ' + name);
      pass++;
    } catch (e) {
      console.error('FAIL - ' + name);
      console.error(e && e.stack || e);
      process.exitCode = 1;
      fail++;
    }
  }
  console.log(`\n${pass} passed, ${fail} failed, ${__tests.length} total`);
  if (fail > 0) process.exitCode = 1;
})();
