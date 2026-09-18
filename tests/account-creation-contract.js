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
if (!fs.readFileSync('public/assets/js/script.js', 'utf8').includes("Passwords do not match.")) {
  throw new Error('setup frontend must validate password confirmation');
}
console.log('warden account-creation contract: ok');