// Runs inside the bundled n8n 2.41.4 SQLite container. The database is read-only:
// all n8n writes go through n8n's own import/publish commands.
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');
const folder = '/home/node/.n8n';
const manifestPath = path.join(folder, 'releaseguard-install.json');
const lockPath = path.join(folder, '.releaseguard-install-lock');
const canonical = value => value && typeof value === 'object'
  ? Array.isArray(value) ? '[' + value.map(canonical).join(',') + ']'
    : '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}'
  : JSON.stringify(value);
const hash = value => createHash('sha256').update(typeof value === 'string' ? value : canonical(value)).digest('hex');
const fail = code => { const e = new Error(code); e.setupCode = code; throw e; };
const decode = value => typeof value === 'string' ? JSON.parse(value) : value;
function snapshot() {
  const db = new DatabaseSync(path.join(folder, 'database.sqlite'), { readOnly: true });
  try {
    const owner = db.prepare('SELECT id FROM user WHERE roleSlug = ? AND email IS NOT NULL AND email != ?').all('global:owner', '');
    const workflows = db.prepare('SELECT id, name, nodes, connections, settings, activeVersionId FROM workflow_entity').all();
    const credentials = db.prepare('SELECT id, name, type, data FROM credentials_entity').all();
    const published = workflows.filter(w => w.activeVersionId).map(w => ({ id: w.id,
      history: db.prepare('SELECT nodes, connections FROM workflow_history WHERE workflowId = ? AND versionId = ?').get(w.id, w.activeVersionId) }));
    return { owner, workflows, credentials, published };
  } finally { db.close(); }
}
function workflowMatches(actual, expected, published = false) {
  if (!actual) return false;
  if (canonical(decode(actual.nodes)) !== canonical(expected.nodes) || canonical(decode(actual.connections)) !== canonical(expected.connections)) return false;
  if (published) return true;
  const settings = decode(actual.settings) || {};
  // n8n adds this harmless subworkflow caller default during import.
  if (expected.settings.callerPolicy === undefined && settings.callerPolicy === 'workflowsFromSameOwner') delete settings.callerPolicy;
  return actual.id === expected.id && actual.name === expected.name && canonical(settings) === canonical(expected.settings);
}
function checkOwned(state, input, manifest, requireAll = false) {
  const workflowIds = new Set(input.workflows.map(w => w.id)), credentialIds = new Set(input.credentials.map(c => c.id));
  if (state.workflows.some(w => !workflowIds.has(w.id)) || state.credentials.some(c => !credentialIds.has(c.id))) fail('STACK_HAS_UNMANAGED_DATA');
  for (const actual of state.workflows) {
    if (!workflowMatches(actual, input.workflows.find(w => w.id === actual.id))) fail('WORKFLOW_CHANGED_USE_MANUAL_SETUP');
  }
  for (const actual of state.credentials) {
    const expected = input.credentials.find(c => c.id === actual.id);
    if (actual.name !== expected.name || actual.type !== expected.type) fail('CREDENTIAL_CHANGED_USE_MANUAL_SETUP');
  }
  if (manifest.credentialHash && hash(state.credentials.map(c => ({ ...c })).sort((a, b) => a.id.localeCompare(b.id))) !== manifest.credentialHash) fail('CREDENTIAL_CHANGED_USE_MANUAL_SETUP');
  if (requireAll && (state.workflows.length !== 4 || state.credentials.length !== 4)) fail('N8N_IMPORT_UNCONFIRMED');
  if (requireAll) for (const w of input.workflows) {
    const row = state.published.find(x => x.id === w.id);
    if (!row || !workflowMatches(row.history, w, true)) fail('N8N_PUBLICATION_UNCONFIRMED');
  }
}
function save(manifest) {
  const temporary = manifestPath + '.tmp-' + process.pid;
  fs.writeFileSync(temporary, JSON.stringify(manifest), { flag: 'wx', mode: 0o600 });
  fs.renameSync(temporary, manifestPath);
}
function n8n(args) {
  const result = spawnSync('n8n', args, { encoding: 'utf8', timeout: 60000, maxBuffer: 2 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] });
  if (result.error || result.status !== 0) fail('N8N_COMMAND_FAILED');
  // Some n8n commands catch errors without a nonzero exit. Their effect is verified
  // in snapshot/checkOwned, so a successful process is never sufficient evidence.
}
let temporary, locked = false;
try {
  const input = JSON.parse(fs.readFileSync(0, 'utf8'));
  if (!['install', 'confirm'].includes(input.action) || input.workflows.length !== 4 || input.credentials.length !== 4) fail('INVALID_INSTALL_BUNDLE');
  if ((process.env.DB_TYPE || 'sqlite') !== 'sqlite' || hash(process.env.N8N_ENCRYPTION_KEY || '') !== input.encryptionKeyHash) fail('N8N_ENVIRONMENT_MISMATCH');
  try { fs.mkdirSync(lockPath, { mode: 0o700 }); locked = true; } catch { fail('INSTALLATION_LOCKED'); }
  let state = snapshot();
  if (state.owner.length !== 1) fail('OWNER_SETUP_REQUIRED');
  let manifest, initial = false;
  try {
    if (!fs.lstatSync(manifestPath).isFile()) fail('INSTALL_MANIFEST_INVALID');
    manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    if (input.action !== 'install') fail('INSTALL_MANIFEST_MISSING');
    if (input.existingRelease) fail('EXISTING_RELEASE_REQUIRES_INSTALL_MANIFEST');
    if (state.workflows.length || state.credentials.length) fail('STACK_HAS_UNMANAGED_DATA');
    manifest = { schema: 1, fingerprint: input.fingerprint, phase: 'PREPARING', ownerId: state.owner[0].id };
    save(manifest); initial = true;
  }
  if (manifest.schema !== 1 || manifest.fingerprint !== input.fingerprint || manifest.ownerId !== state.owner[0].id) fail('ENV_OR_BUNDLE_CHANGED_USE_MANUAL_SETUP');
  checkOwned(state, input, manifest, manifest.phase !== 'PREPARING');
  if (input.action === 'confirm') {
    checkOwned(state, input, manifest, true);
    if (manifest.phase !== 'COMPLETE') { manifest.phase = 'COMPLETE'; save(manifest); }
    console.log(JSON.stringify({ ok: true, phase: 'COMPLETE' }));
  } else if (manifest.phase === 'COMPLETE') {
    console.log(JSON.stringify({ ok: true, initial: false, restartRequired: false, phase: 'COMPLETE' }));
  } else {
    temporary = fs.mkdtempSync('/dev/shm/releaseguard-install-');
    fs.chmodSync(temporary, 0o700);
    if (!manifest.credentialHash) {
      const credentialsPath = path.join(temporary, 'credentials.json');
      fs.writeFileSync(credentialsPath, JSON.stringify(input.credentials), { flag: 'wx', mode: 0o600 });
      n8n(['import:credentials', '--input=' + credentialsPath, '--userId=' + manifest.ownerId]);
      state = snapshot();
      if (state.credentials.length !== 4) fail('N8N_CREDENTIAL_IMPORT_UNCONFIRMED');
      checkOwned(state, input, manifest);
      manifest.credentialHash = hash(state.credentials.map(c => ({ ...c })).sort((a, b) => a.id.localeCompare(b.id))); save(manifest);
    }
    if (state.workflows.length !== 4) {
      const workflowsPath = path.join(temporary, 'workflows.json');
      fs.writeFileSync(workflowsPath, JSON.stringify(input.workflows), { flag: 'wx', mode: 0o600 });
      n8n(['import:workflow', '--input=' + workflowsPath, '--userId=' + manifest.ownerId]);
      state = snapshot();
    }
    checkOwned(state, input, manifest);
    if (state.workflows.length !== 4) fail('N8N_WORKFLOW_IMPORT_UNCONFIRMED');
    for (const w of state.workflows) if (!w.activeVersionId) n8n(['publish:workflow', '--id=' + w.id]);
    state = snapshot(); checkOwned(state, input, manifest, true);
    manifest.phase = 'PUBLISHED'; save(manifest);
    console.log(JSON.stringify({ ok: true, initial, restartRequired: true, phase: 'PUBLISHED' }));
  }
} catch (error) {
  console.log(JSON.stringify({ ok: false, error: error.setupCode || 'N8N_STATE_UNCONFIRMED' }));
} finally {
  if (temporary) fs.rmSync(temporary, { recursive: true, force: true });
  if (locked) fs.rmdirSync(lockPath);
}
