// Embedded editor/agent layout contract: the embedded agent must share the
// editor's declared row heights so the header, empty-file/workspace row and
// session-tabs boundary align exactly, and the split renders as one clean
// border line. Runs against the real public/assets/css/style.css.
//
// Run with: node tests/editor-layout.test.js

const fs = require('fs');
const assert = require('assert');

const css = fs.readFileSync('public/assets/css/style.css', 'utf8');
const html = fs.readFileSync('content/index.html', 'utf8');

function blocks(selPrefix) {
  const out = [];
  let start = 0;
  for (;;) {
    const brace = css.indexOf('{', start);
    if (brace < 0) break;
    const close = css.indexOf('}', brace);
    if (close < 0) break;
    const selector = css.slice(start, brace).trim();
    const body = css.slice(brace + 1, close);
    if (selector.includes(selPrefix)) out.push({ selector, body });
    start = close + 1;
  }
  return out;
}

// Shared row-height variables are declared on .editor-workbench so both the
// editor main pane and the embedded agent pane derive their header rows from
// the same source of truth.
const wb = blocks('.editor-workbench').find((b) => b.body.includes('--editor-tabs-h'));
assert(wb, '.editor-workbench must declare --editor-tabs-h');
assert(wb.body.includes('--editor-tabs-h:40px'), 'editor header row must be 40px');
assert(wb.body.includes('--editor-toolbar-h:42px'), 'editor toolbar/empty-file row must be 42px');
assert(wb.body.includes('--editor-statusbar-h:24px'), 'editor statusbar row must be 24px');
assert(wb.body.includes('--agent-sessionbar-h:34px'), 'compact agent sessionbar must be 34px');

// The embedded agent shares the editor header and toolbar heights, and starts
// its session-tabs row on the shared toolbar boundary.
for (const b of blocks('.editor-agent-panel')) {
  if (!b.body.includes('grid-template-rows')) continue;
  assert(
    b.body.includes('grid-template-rows:var(--editor-tabs-h) var(--editor-toolbar-h) var(--agent-sessionbar-h)'),
    '.editor-agent-panel must share editor header+toolbar+sessionbar heights: ' + b.body
  );
}

// The editor main pane uses the same declared header and toolbar rows.
for (const b of blocks('.editor-main')) {
  if (!b.body.includes('grid-template-rows')) continue;
  assert(
    b.body.includes('grid-template-rows:var(--editor-tabs-h) var(--editor-toolbar-h)'),
    '.editor-main must share header+toolbar heights: ' + b.body
  );
}

// Border contract: every horizontal boundary in the editor/agent split uses
// the same 1px var(--line) border, so the seam is one clean line.
const border = (sel, name) => {
  const b = blocks(sel).find((x) => x.body.includes('border-bottom'));
  assert(b, name + ' must declare a border-bottom');
  assert(b.body.includes('border-bottom:1px solid var(--line)'), name + ' border must be 1px solid var(--line)');
  return b;
};
border('.editor-tabs', 'editor tabs');
border('.editor-toolbar', 'editor toolbar');
border('.editor-agent-head', 'agent header');
const ws = border('.editor-agent-workspace', 'agent workspace row');

// Element heights equal the shared row heights they live in.
assert(blocks('.editor-tabs').some((b) => b.body.includes('height:40px')), '.editor-tabs height must equal --editor-tabs-h');
assert(blocks('.editor-toolbar').some((b) => b.body.includes('height:42px')), '.editor-toolbar height must equal --editor-toolbar-h');
assert(
  blocks('.agent-sessionbar').some((b) => b.body.includes('height:var(--agent-sessionbar-h)')),
  '.agent-sessionbar.compact must use the shared --agent-sessionbar-h'
);

// Text/controls remain vertically centred after the workspace row height was
// raised to match the editor toolbar row.
assert(ws.body.includes('display:flex') && ws.body.includes('align-items:center'), 'agent workspace row must vertically centre its content');

// Both agent surfaces show a concise readiness label. The embedded state is
// grouped at the right edge and has the same status dot as the standalone view.
assert(html.includes('id="editor-agent-state-dot"'), 'embedded agent status dot is missing');
assert(html.includes('class="editor-agent-head-actions"'), 'embedded agent status/actions group is missing');
assert(
  blocks('.editor-agent-head-actions').some((b) => b.body.includes('justify-content:flex-end')),
  'embedded agent status/actions must be right aligned'
);
assert(
  blocks('.agent-panel>.agent-body').some((b) => b.body.includes('flex:1 1 auto')),
  'standalone agent body must fill the panel so its prompt stays at the bottom'
);

// Composer contract: the provider occupies its own centred row. Copy session
// and Tasks form the left action group, while Run remains right aligned on the
// row below. This protects the intended two-row layout at narrow panel widths.
const providerRow = html.match(/<div class="editor-agent-provider-row">([\s\S]*?)<\/div>/);
assert(providerRow, 'editor agent provider row must exist');
assert(providerRow[1].includes('id="editor-agent-provider"'), 'provider select must be in the provider row');

const actionRow = html.match(/<div class="editor-agent-action-row">([\s\S]*?)<\/form>/);
assert(actionRow, 'editor agent action row must exist');
assert(actionRow[1].includes('class="agent-compose-actions"'), 'left action group must exist');
assert(actionRow[1].includes('id="editor-agent-copy-session"'), 'Copy session must be in the left action group');
assert(actionRow[1].includes('id="editorAgentTaskReopen"'), 'Tasks must be beside Copy session');
assert(actionRow[1].includes('class="agent-compose-run"'), 'right run group must exist');
assert(actionRow[1].includes('id="editor-agent-run"'), 'Run must be in the right action group');
assert(
  blocks('.editor-agent-compose>.editor-agent-provider-row').some((b) => b.body.includes('width:100%')),
  'provider row must span the composer width'
);
assert(
  blocks('.editor-agent-compose>.editor-agent-provider-row .agent-provider-select').some(
    (b) => b.body.includes('width:100%') && b.body.includes('max-width:none')
  ),
  'provider dropdown must match the prompt width'
);
assert(
  blocks('.editor-agent-compose>.editor-agent-action-row').some((b) => b.body.includes('justify-content:space-between')),
  'action row must separate left controls from Run'
);

console.log('warden editor/agent layout contract: ok');
