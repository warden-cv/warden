const fs = require('fs');

// The standardized account-creation contract: every interactive signup form
// presents Username, Email, Password and Confirm password, in that order, and
// never a display-name field. The login form remains Username-or-email.
const html = fs.readFileSync('content/index.html', 'utf8');
const setup = html.split('<form id="setup-form"')[1].split('</form>')[0];
const fields = [...setup.matchAll(/id="(setup-[a-z-]+)"/g)].map(m => m[1]);
const wanted = ['setup-username', 'setup-email', 'setup-password', 'setup-confirm'];
for (const id of wanted) {
  if (!fields.includes(id)) throw new Error('setup form missing ' + id);
}
if (fields.includes('setup-display')) throw new Error('setup form still requests a display name');
const order = fields.indexOf('setup-username') < fields.indexOf('setup-email') &&
              fields.indexOf('setup-email') < fields.indexOf('setup-password') &&
              fields.indexOf('setup-password') < fields.indexOf('setup-confirm');
if (!order) throw new Error('setup fields are out of canonical order');
if (!html.includes('id="username"') || !html.includes('placeholder="Username or email"')) {
  throw new Error('login form must accept username or email');
}
const appJs = fs.readFileSync('public/assets/js/script.js', 'utf8');
if (!appJs.includes("Passwords do not match.")) {
  throw new Error('setup frontend must validate password confirmation');
}

// The application Access panel (create-account in the main app) is canonical.
const accessForm = appJs.split('id="access-create-account"')[1].split('</form>')[0];
for (const id of ['username', 'email', 'password', 'confirm']) {
  if (!accessForm.includes('name="' + id + '"')) throw new Error('Access create-account form missing ' + id);
}
if (accessForm.includes('displayName') || /Display name/.test(accessForm)) {
  throw new Error('Access create-account form still requests a display name');
}
if (!appJs.includes("Action:'create-account',Username")) throw new Error('Access create-account must send Username');
if (appJs.includes("DisplayName:f.get('displayName')")) throw new Error('Access create-account payload still sends a display name');

// The separate /manage shell (public/assets/js/manage.js is canonical; the
// stray content copy was removed).
const manageJs = fs.readFileSync('public/assets/js/manage.js', 'utf8');
const addUser = manageJs.split("openModal('Add user'")[1].split(',async')[0];
for (const id of ['username', 'email', 'password', 'confirm']) {
  if (!addUser.includes('name="' + id + '"')) throw new Error('/manage Add user form missing ' + id);
}
if (/Display name/.test(addUser)) throw new Error('/manage Add user form still requests a display name');
if (manageJs.includes("DisplayName:data.get('display')")) throw new Error('/manage create-account payload still sends a display name');
if (!manageJs.includes("'Passwords do not match.'") && !manageJs.includes('"Passwords do not match."')) {
  throw new Error('/manage frontend must validate password confirmation');
}
// Source/generated parity: the stray Nift content copy of manage.js must be gone.
if (fs.existsSync('content/assets/js/manage.js')) {
  throw new Error('content/assets/js/manage.js stray copy still exists');
}

console.log('warden account-creation contract: ok');