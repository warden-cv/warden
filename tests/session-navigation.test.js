const fs = require('fs');
const assert = require('assert');

const js = fs.readFileSync('public/assets/js/script.js', 'utf8');
const html = fs.readFileSync('content/index.html', 'utf8');

assert(js.includes("function startFreshAgentSession(){agentSessions={};agentClosedSessions=[];activeAgentSessionId='';agentServerReady=false"), 'authenticated load must create a fresh agent session');
const showApp = js.split('\n').find(line => line.startsWith('function showApp(')) || '';
assert(showApp.includes('startFreshAgentSession()'), 'authenticated app load must use the fresh-session path');
assert(!showApp.includes('syncAgentConversations()'), 'authenticated app load must not restore server conversations');
assert(js.includes('Object.values(agentSessions).some(s=>s.busy)'), 'reload guard must inspect every agent tab');
assert(!html.includes('data-view="sessions"') && !html.includes('id="view-sessions"'), 'recent sessions must not be a separate sidebar view');
assert(html.includes('id="agent-history-modal"') && html.includes('id="agent-history-cancel"'), 'cancellable recent sessions overlay is missing');
assert(html.includes('id="agent-history-prev"') && html.includes('id="agent-history-next"'), 'history pagination controls are missing');
assert(js.includes("item('New workspace','Choose another directory',newAgentWorkspace);item('Recent sessions','Restore a previous conversation',openAgentHistoryPicker)"), 'recent sessions must appear directly beneath New workspace in both Agent menus');
assert(js.includes('closeAgentHistoryPicker();renderAgentSession();loadAgentStatus()'), 'restoring a session must close the overlay without forcing a different Agent surface');
const terminalLoad = js.split('\n').find(line => line.startsWith('async function loadTerminalSessions()')) || '';
assert(terminalLoad.includes('createTerminalSession(homePath,false)'), 'authenticated load must create a fresh terminal session');
assert(!terminalLoad.includes('terminalSessions.set(item.id,item)'), 'authenticated load must not restore previous terminal sessions');
assert(terminalLoad.includes("x.state!=='connected'"), 'startup cleanup must preserve terminal sessions active in other browser tabs');

console.log('warden fresh-session and history navigation contract: ok');
