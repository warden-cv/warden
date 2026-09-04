// Reload-confirmation guard contract tests, driven against the real
// public/assets/js/script.js reload-guard region in a minimal DOM/event
// sandbox. Covers keyboard reload interception, Warden's own confirmation,
// the one-use beforeunload bypass, and login/setup non-activation.
//
// Run with: node tests/reload-guard.test.js

const fs = require('fs');
const vm = require('vm');
const assert = require('assert');

const SCRIPT = fs.readFileSync('public/assets/js/script.js', 'utf8');
const REGION_START = SCRIPT.indexOf('let reloadGuardActive=false;');
const REGION_END = SCRIPT.indexOf('// END reload guard');
if (REGION_START < 0 || REGION_END < 0) throw new Error('reload-guard region not found');
const REGION = SCRIPT.slice(REGION_START, REGION_END);

function loadGuard(opts) {
  opts = opts || {};
  const listeners = { keydown: [], beforeunload: [] };
  const toasts = [];
  let reloadCalls = 0;
  const body = { children: [], append(...x) { for (const k of x) if (k != null) this.children.push(k); } };
  function makeNode(tag) {
    const n = {
      tagName: String(tag || 'div').toUpperCase(),
      children: [], dataset: {}, style: {}, hidden: false, _innerHTML: '', _qs: {},
      classList: { add() {}, remove() {}, toggle() {} },
      set innerHTML(v) { this._innerHTML = String(v); this.children = []; },
      get innerHTML() { return this._innerHTML; },
      append(...x) { for (const k of x) if (k != null) this.children.push(k); },
      appendChild(x) { this.children.push(x); return x; },
      remove() { const i = body.children.indexOf(this); if (i >= 0) body.children.splice(i, 1); },
      addEventListener() {},
      focus() {},
      querySelector(sel) { if (!this._qs[sel]) this._qs[sel] = makeNode(sel); return this._qs[sel]; },
    };
    return n;
  }
  const ctx = {
    console,
    setTimeout,
    agentSessions: opts.agentSessions || { running: { busy: true } },
    esc: (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])),
    document: { createElement: makeNode, body },
    location: { reload() { reloadCalls++; if (opts.reloadThrows) throw new Error('reload blocked'); } },
    toast: (m) => { toasts.push(String(m)); },
    window: {
      addEventListener(type, fn) { (listeners[type] = listeners[type] || []).push(fn); },
      removeEventListener(type, fn) { if (listeners[type]) listeners[type] = listeners[type].filter((f) => f !== fn); },
    },
  };
  ctx.globalThis = ctx;
  vm.createContext(ctx);
  vm.runInContext(REGION, ctx);
  const fire = (type, ev) => {
    ev = ev || {};
    if (!ev.preventDefault) ev.preventDefault = () => { ev._prevented = true; };
    if (!ev.stopPropagation) ev.stopPropagation = () => { ev._stopped = true; };
    for (const fn of [...(listeners[type] || [])]) fn(ev);
    return ev;
  };
  return {
    ctx,
    fire,
    modal: () => body.children.find((c) => String(c.className || '').includes('reload-confirm-backdrop')),
    modals: () => body.children.filter((c) => String(c.className || '').includes('reload-confirm-backdrop')),
    reloadCalls: () => reloadCalls,
    toasts,
    run: (code) => vm.runInContext(code, ctx),
  };
}

const __tests = [];
function test(name, fn) { __tests.push({ name, fn }); }

test('plain Ctrl+R is intercepted and shows the confirmation', () => {
  const g = loadGuard();
  g.run('installReloadGuard()');
  const ev = g.fire('keydown', { key: 'r', ctrlKey: true });
  assert.strictEqual(ev._prevented, true, 'Ctrl+R must be intercepted');
  assert.strictEqual(ev._stopped, true, 'must stop propagation');
  assert(g.modal(), 'confirmation must be shown');
  assert(g.modal().innerHTML.includes('Reload Warden? Unsaved edits and active work may be lost.'), 'confirmation text must be Warden-owned');
});

test('idle agent tabs do not intercept refresh', () => {
  const g = loadGuard({ agentSessions: { idle: { busy: false } } });
  g.run('installReloadGuard()');
  const key = g.fire('keydown', { key: 'r', ctrlKey: true });
  const unload = g.fire('beforeunload', {});
  assert.strictEqual(key._prevented, undefined);
  assert.strictEqual(unload._prevented, undefined);
  assert.strictEqual(g.modal(), undefined);
});

test('shifted Ctrl+R is intercepted', () => {
  const g = loadGuard();
  g.run('installReloadGuard()');
  const ev = g.fire('keydown', { key: 'R', ctrlKey: true, shiftKey: true });
  assert.strictEqual(ev._prevented, true);
  assert(g.modal());
});

test('macOS Cmd+R variants are intercepted', () => {
  for (const e of [{ key: 'r', metaKey: true }, { key: 'R', metaKey: true, shiftKey: true }]) {
    const g = loadGuard();
    g.run('installReloadGuard()');
    const ev = g.fire('keydown', e);
    assert.strictEqual(ev._prevented, true, 'Cmd+R must be intercepted for ' + JSON.stringify(e));
    assert(g.modal());
  }
});

test('F5 is intercepted', () => {
  const g = loadGuard();
  g.run('installReloadGuard()');
  const ev = g.fire('keydown', { key: 'F5' });
  assert.strictEqual(ev._prevented, true);
  assert(g.modal());
});

test('cancellation does not reload', () => {
  const g = loadGuard();
  g.run('installReloadGuard()');
  g.fire('keydown', { key: 'r', ctrlKey: true });
  g.modal().querySelector('[data-reload-cancel]').onclick();
  assert.strictEqual(g.reloadCalls(), 0, 'cancel must not reload');
  assert.strictEqual(g.run('reloadGuardActive'), true, 'guard must remain active after cancel');
});

test('confirmation reloads exactly once and arms the bypass', () => {
  const g = loadGuard();
  g.run('installReloadGuard()');
  g.fire('keydown', { key: 'r', ctrlKey: true });
  g.modal().querySelector('form').onsubmit({ preventDefault() {} });
  assert.strictEqual(g.reloadCalls(), 1, 'confirm must reload exactly once');
  assert.strictEqual(g.run('reloadConfirmArmed'), true, 'one-use bypass must be armed');
});

test('confirmed reload bypasses beforeunload exactly once, then protects again', () => {
  const g = loadGuard();
  g.run('installReloadGuard()');
  g.fire('keydown', { key: 'r', ctrlKey: true });
  g.modal().querySelector('form').onsubmit({ preventDefault() {} });
  const first = g.fire('beforeunload', {});
  assert.strictEqual(first._prevented, undefined, 'armed unload must bypass beforeunload');
  assert.strictEqual(g.run('reloadConfirmArmed'), false, 'bypass must be consumed once');
  const second = g.fire('beforeunload', {});
  assert.strictEqual(second._prevented, true, 'a later unload must be protected again');
});

test('bypass resets if reload initiation fails and control returns', async () => {
  const g = loadGuard();
  g.run('installReloadGuard()');
  g.fire('keydown', { key: 'r', ctrlKey: true });
  g.modal().querySelector('form').onsubmit({ preventDefault() {} });
  assert.strictEqual(g.run('reloadConfirmArmed'), true);
  await new Promise((r) => setTimeout(r, 3200));
  assert.strictEqual(g.run('reloadConfirmArmed'), false, 'bypass must reset if control returns');
  const u = g.fire('beforeunload', {});
  assert.strictEqual(u._prevented, true, 'a later unload must be protected again');
});

test('toolbar/browser reload invokes beforeunload protection', () => {
  const g = loadGuard();
  g.run('installReloadGuard()');
  const ev = g.fire('beforeunload', {});
  assert.strictEqual(ev._prevented, true, 'toolbar reload must be blocked');
  assert.strictEqual(ev.returnValue, '', 'returnValue must be set');
});

test('unrelated shortcuts are unaffected', () => {
  const g = loadGuard();
  g.run('installReloadGuard()');
  for (const e of [{ key: 'c', ctrlKey: true }, { key: 'r' }, { key: 'r', altKey: true }, { key: 'F2' }, { key: 'r', shiftKey: true }]) {
    const ev = g.fire('keydown', e);
    assert.strictEqual(ev._prevented, undefined, 'unrelated shortcut must not be intercepted: ' + JSON.stringify(e));
    assert.strictEqual(g.modal(), undefined, 'no confirmation for unrelated shortcut');
  }
});

test('repeated reload keydowns are prevented and open only one confirmation', () => {
  const g = loadGuard();
  g.run('installReloadGuard()');
  g.fire('keydown', { key: 'r', ctrlKey: true });
  const held = g.fire('keydown', { key: 'r', ctrlKey: true, repeat: true });
  assert.strictEqual(held._prevented, true, 'held-key repeat must still be prevented');
  const again = g.fire('keydown', { key: 'r', ctrlKey: true });
  assert.strictEqual(again._prevented, true, 'recognized keydown still intercepted while prompt open');
  assert.strictEqual(g.modals().length, 1, 'must not open multiple confirmations');
});

test('removing the guard closes an open dialog and invalidates its callback', () => {
  const g = loadGuard();
  g.run('installReloadGuard()');
  g.fire('keydown', { key: 'r', ctrlKey: true });
  assert(g.modal(), 'dialog should be open');
  const staleForm = g.modal().querySelector('form');
  g.run('removeReloadGuard()');
  assert.strictEqual(g.modals().length, 0, 'removeReloadGuard must close the open dialog');
  assert.strictEqual(g.run('reloadPromptOpen'), false, 'no stale prompt state');
  assert.strictEqual(g.run('reloadConfirmArmed'), false, 'no bypass armed');
  // Submitting the stale form after removal must not reload.
  staleForm.onsubmit({ preventDefault() {} });
  assert.strictEqual(g.reloadCalls(), 0, 'stale form submit must not reload');
});

test('showLogin and showSetup remove an open dialog and stale submit cannot reload', () => {
  // The guard is installed when the authenticated app is shown; login/setup
  // transitions call removeReloadGuard. Verify the full removal path closes an
  // already-open dialog and invalidates its callback.
  assert(/\bshowLogin\(\)\{[\s\S]*?removeReloadGuard\(\)/.test(SCRIPT), 'showLogin must remove the guard');
  assert(/\bshowSetup\(status=\{\}\)\{removeReloadGuard\(\)/.test(SCRIPT), 'showSetup must remove the guard');
  const g = loadGuard();
  g.run('installReloadGuard()');
  g.fire('keydown', { key: 'r', ctrlKey: true });
  const staleForm = g.modal().querySelector('form');
  g.run('removeReloadGuard()');
  assert.strictEqual(g.modals().length, 0, 'dialog removed');
  staleForm.onsubmit({ preventDefault() {} });
  assert.strictEqual(g.reloadCalls(), 0, 'stale submit after removal must not reload');
  const u = g.fire('beforeunload', {});
  assert.strictEqual(u._prevented, undefined, 'guard removed means unload is not blocked');
});

test('synchronous reload failure clears the bypass and keeps the guard active', async () => {
  const g = loadGuard({ reloadThrows: true });
  g.run('installReloadGuard()');
  g.fire('keydown', { key: 'r', ctrlKey: true });
  g.modal().querySelector('form').onsubmit({ preventDefault() {} });
  assert.strictEqual(g.run('reloadConfirmArmed'), false, 'bypass must be cleared immediately on failure');
  assert.strictEqual(g.run('reloadGuardActive'), true, 'guard must remain active');
  assert.strictEqual(g.run('reloadPromptOpen'), false, 'no stale prompt flag');
  assert.strictEqual(g.modals().length, 0, 'no modal left behind');
  assert.strictEqual(g.toasts.length, 1, 'a reload-failure toast should be shown');
  const u = g.fire('beforeunload', {});
  assert.strictEqual(u._prevented, true, 'a later unload must be protected again');
});

test('reload-confirm actions share the confirmation action-row styling', () => {
  const css = fs.readFileSync('public/assets/css/style.css', 'utf8');
  assert(/\.password-confirm-actions,\.reload-confirm-actions\{display:flex;justify-content:flex-end;gap:7px;margin-top:14px\}/.test(css), 'reload-confirm-actions must share the action-row contract');
});

test('login/setup state does not install or activate the protection', () => {
  const g = loadGuard();
  const ev = g.fire('keydown', { key: 'r', ctrlKey: true });
  assert.strictEqual(ev._prevented, undefined, 'keydown must not be intercepted before install');
  assert.strictEqual(g.modal(), undefined);
  const u = g.fire('beforeunload', {});
  assert.strictEqual(u._prevented, undefined, 'beforeunload must not be blocked before install');
  g.run('installReloadGuard()');
  g.run('removeReloadGuard()');
  const ev2 = g.fire('keydown', { key: 'r', ctrlKey: true });
  assert.strictEqual(ev2._prevented, undefined, 'keydown must not be intercepted after remove');
  const u2 = g.fire('beforeunload', {});
  assert.strictEqual(u2._prevented, undefined, 'beforeunload must not be blocked after remove');
});

test('guard is wired only to the authenticated app transition', () => {
  assert(/\bshowApp\(s=\{\}\)\{installReloadGuard\(\)/.test(SCRIPT), 'showApp must install the guard');
  assert(/\bshowLogin\(\)\{[\s\S]*?removeReloadGuard\(\)/.test(SCRIPT), 'showLogin must remove the guard');
  assert(/\bshowSetup\(status=\{\}\)\{removeReloadGuard\(\)/.test(SCRIPT), 'showSetup must remove the guard');
});

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
