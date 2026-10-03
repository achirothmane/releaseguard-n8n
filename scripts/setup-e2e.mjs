// Actual fresh Docker Compose installation. Owner creation uses the n8n test API
// only in this disposable harness; the shipped installer leaves it to the UI.
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { cp, mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { randomUUID, createHash } from 'node:crypto';
import { parseEnv } from 'node:util';
import { Secrets } from '../src/security.mjs';

const root = resolve(new URL('..', import.meta.url).pathname);
await mkdir(join(root, 'tmp'), { recursive: true }); await mkdir(join(root, 'evidence'), { recursive: true });
const directory = await mkdtemp(join(root, 'tmp', 'setup-e2e-'));
for (const name of ['scripts', 'src', 'sql', 'web', 'workflows', 'config', 'package.json', 'package-lock.json', 'Dockerfile', '.dockerignore', 'compose.yaml']) {
  await cp(join(root, name), join(directory, name), { recursive: true });
}
execFileSync(process.execPath, [join(directory, 'scripts/generate-env.mjs')], { cwd: directory, stdio: 'pipe' });
await writeFile(join(directory, '.env'), await readFile(join(directory, '.env'), 'utf8') + 'RG_GUARD_PORT=18080\nRG_N8N_PORT=15678\n');
const envText = await readFile(join(directory, '.env'), 'utf8'), env = parseEnv(envText);
const project = 'rg-setup-' + randomUUID().slice(0, 8), api = 'http://127.0.0.1:18080', n8n = 'http://127.0.0.1:15678';
const results = [], started = Date.now();
const redact = text => Object.values(env).filter(x => x.length >= 32).reduce((out, value) => out.replaceAll(value, '[redacted]'), text);
const compose = (args, input) => execFileSync('docker', ['compose', '--project-name', project, '--env-file', join(directory, '.env'),
  '-f', join(directory, 'compose.yaml'), ...args], { cwd: directory, env: { ...process.env, ...env }, encoding: 'utf8', input,
  timeout: 240000, stdio: ['pipe', 'pipe', 'pipe'], maxBuffer: 8 * 1024 * 1024 });
function install(command, pass = true) {
  const r = spawnSync(process.execPath, [join(directory, 'scripts/setup.mjs'), command, '--project', project], {
    cwd: directory, encoding: 'utf8', timeout: 300000, maxBuffer: 4 * 1024 * 1024,
  });
  const raw = (r.stdout || '') + (r.stderr || '');
  for (const value of Object.values(env).filter(x => x.length >= 32)) assert.ok(!raw.includes(value), 'installer leaked a secret');
  assert.equal(r.status, pass ? 0 : 1, redact(raw));
  const output = JSON.parse((pass ? r.stdout : r.stderr).trim());
  return output;
}
const inspectSource = `
const {DatabaseSync}=require('node:sqlite'),{createHash}=require('node:crypto'),fs=require('node:fs');
const db=new DatabaseSync('/home/node/.n8n/database.sqlite',{readOnly:true});
const ws=db.prepare('SELECT id,name,nodes,versionId,activeVersionId FROM workflow_entity ORDER BY id').all();
const cs=db.prepare('SELECT id,data FROM credentials_entity ORDER BY id').all();
const m='/home/node/.n8n/releaseguard-install.json';
console.log(JSON.stringify({workflows:ws,credentialCount:cs.length,credentialHash:createHash('sha256').update(JSON.stringify(cs)).digest('hex'),
 manifest:fs.existsSync(m)?JSON.parse(fs.readFileSync(m,'utf8')):null,
 secretFiles:fs.readdirSync('/dev/shm').filter(n=>n.startsWith('releaseguard-install-'))}));db.close();`;
const inspect = () => JSON.parse(compose(['exec', '-T', 'n8n', 'node', '-e', inspectSource]).trim());
async function call(path, data, headers = {}) {
  const r = await fetch(api + path, { method: data ? 'POST' : 'GET', redirect: 'error', signal: AbortSignal.timeout(30000),
    headers: { 'content-type': 'application/json', authorization: 'Bearer ' + env.ADMIN_TOKEN, ...headers }, body: data ? JSON.stringify(data) : undefined });
  return { status: r.status, body: await r.json() };
}
const record = (name, detail = {}) => { results.push({ name, result: 'PASS', ...detail }); console.log('PASS setup: ' + name); };
try {
  const start = install('start'); assert.equal(start.verdict, 'STACK_STARTED'); assert.equal(start.keys, 'PRESERVED');
  assert.equal(await readFile(join(directory, '.env'), 'utf8'), envText);
  record('fresh stack starts with existing keys preserved');
  const pending = install('install', false); assert.equal(pending.error, 'OWNER_SETUP_REQUIRED');
  const empty = inspect(); assert.equal(empty.workflows.length, 0); assert.equal(empty.credentialCount, 0); assert.equal(empty.manifest, null);
  record('unconfigured owner blocks before importing any data');
  const owner = await fetch(n8n + '/rest/owner/setup', { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'setup-owner@example.test', firstName: 'Setup', lastName: 'CI', password: 'Setup-CI-Only-2026!' }) });
  assert.ok(owner.ok, 'disposable owner setup failed');
  const first = install('install'); assert.equal(first.verdict, 'READY_FOR_CANARY'); assert.equal(first.installation, 'CREATED');
  const baseline = inspect(); assert.equal(baseline.workflows.length, 4); assert.equal(baseline.credentialCount, 4);
  assert.ok(baseline.workflows.every(w => w.activeVersionId)); assert.equal(baseline.manifest.phase, 'COMPLETE');
  assert.equal(baseline.secretFiles.length, 0); assert.equal(await readFile(join(directory, '.env'), 'utf8'), envText);
  record('four workflows and four bound credentials install and publish automatically', { tests: first.tests });
  const denied = await fetch(n8n + '/webhook/releaseguard', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ leadId: 'NO-AUTH', score: 81 }) });
  assert.ok([401, 403].includes(denied.status)); record('Gateway requires the generated client credential');
  const before = (await call('/v1/releases/demo')).body.release;
  const repeated = install('install'); assert.equal(repeated.installation, 'VERIFIED'); assert.equal(repeated.verdict, 'READY_FOR_CANARY');
  const after = inspect(); assert.deepEqual(after.workflows, baseline.workflows); assert.equal(after.credentialHash, baseline.credentialHash);
  const repeatRelease = (await call('/v1/releases/demo')).body.release;
  assert.equal(repeatRelease.revision, before.revision); assert.equal(repeatRelease.stage, before.stage);
  record('repeat install does not reimport, rotate credentials, or reset the release');
  await writeFile(join(directory, '.env'), envText.replace(env.UPSTREAM_TOKEN, 'e'.repeat(64)));
  const rotated = install('install', false); assert.equal(rotated.error, 'ENV_OR_BUNDLE_CHANGED_USE_MANUAL_SETUP');
  assert.equal(inspect().credentialHash, baseline.credentialHash);
  await writeFile(join(directory, '.env'), envText);
  record('changed secrets block without replacing stored credentials');
  const saved = baseline.workflows.find(w => w.id === 'rg-stable');
  const changedNodes = JSON.parse(saved.nodes); changedNodes.find(n => n.type === 'n8n-nodes-base.code').parameters.jsCode = 'throw new Error("edited after install")';
  const mutate = `const {DatabaseSync}=require('node:sqlite');const db=new DatabaseSync('/home/node/.n8n/database.sqlite');const s=require('node:fs').readFileSync(0,'utf8');db.prepare('UPDATE workflow_entity SET nodes=? WHERE id=?').run(s,'rg-stable');db.close();`;
  compose(['exec', '-T', 'n8n', 'node', '-e', mutate], JSON.stringify(changedNodes));
  const drift = install('install', false); assert.equal(drift.error, 'WORKFLOW_CHANGED_USE_MANUAL_SETUP');
  assert.equal(inspect().workflows.find(w => w.id === 'rg-stable').nodes, JSON.stringify(changedNodes));
  compose(['exec', '-T', 'n8n', 'node', '-e', mutate], saved.nodes);
  record('edited workflow blocks and is not overwritten');
  // Inject a real Candidate failure through the production Gateway, then verify
  // that rerunning the installer cannot restart the release or admit Candidate.
  const secrets = new Secrets(env.RESPONSE_KEY_HEX); let key;
  for (let i = 0;; i++) { key = 'setup-fault-' + i; if (secrets.bucket('demo', key) < 5) break; }
  const faulty = await fetch(n8n + '/webhook/releaseguard', { method: 'POST', headers: { 'content-type': 'application/json',
    'x-releaseguard-client': env.CLIENT_TOKEN, 'x-request-id': key }, body: JSON.stringify({ leadId: 'SETUP-FAULT', score: 81, faultCandidate: 'invalid' }) });
  const fb = await faulty.json(); assert.equal(faulty.status, 200); assert.equal(fb.fallback, true);
  const stopped = (await call('/v1/releases/demo')).body.release; assert.equal(stopped.status, 'ROLLED_BACK');
  const stoppedInstall = install('install'); assert.equal(stoppedInstall.verdict, 'INSTALLATION_VERIFIED'); assert.equal(stoppedInstall.releaseStatus, 'ROLLED_BACK');
  const preserved = (await call('/v1/releases/demo')).body.release; assert.equal(preserved.revision, stopped.revision); assert.equal(preserved.candidatePct, 0);
  record('installer rerun preserves automatic rollback and Stable-only routing');
  const final = inspect(); assert.equal(final.secretFiles.length, 0); assert.equal(final.credentialHash, baseline.credentialHash);
  assert.equal(await readFile(join(directory, '.env'), 'utf8'), envText);
  record('plaintext import material is removed and all persistent keys remain unchanged');
  await writeFile(join(root, 'evidence/setup-e2e-results.json'), JSON.stringify({ runtime: 'fresh actual Docker Compose + n8n 2.41.4 + PostgreSQL',
    elapsedSeconds: Math.round((Date.now() - started) / 1000), cases: results, initialVerdict: first, finalVerdict: stoppedInstall }, null, 2));
} catch (error) {
  let logs = ''; try { logs = compose(['logs', '--no-color', '--tail', '150']); } catch {}
  await writeFile(join(root, 'evidence/setup-failure.log'), redact(logs));
  console.error(redact(String(error.stack))); throw error;
} finally {
  compose(['down', '--volumes', '--remove-orphans']);
}
