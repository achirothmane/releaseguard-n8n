import { execFileSync } from 'node:child_process';
import { createHash, createHmac, randomBytes, randomUUID } from 'node:crypto';
import { chmod, lstat, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseEnv } from 'node:util';
import { policy } from '../src/policy.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export const secretKeys = ['POSTGRES_PASSWORD', 'ADMIN_TOKEN', 'DATA_TOKEN', 'UPSTREAM_TOKEN',
  'ALERT_TOKEN', 'RESPONSE_KEY_HEX', 'N8N_ENCRYPTION_KEY', 'CLIENT_TOKEN'];
export const canonical = value => value && typeof value === 'object'
  ? Array.isArray(value) ? '[' + value.map(canonical).join(',') + ']'
    : '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}'
  : JSON.stringify(value);
export const hash = value => createHash('sha256').update(typeof value === 'string' ? value : canonical(value)).digest('hex');
const fail = code => { const error = new Error(code); error.setupCode = code; throw error; };

export function validateEnvironment(input) {
  const env = { ...input };
  for (const key of secretKeys) {
    if (!/^[A-Za-z0-9_-]{32,128}$/.test(env[key] || '')) fail('INVALID_' + key);
  }
  for (const key of ['RESPONSE_KEY_HEX', 'POSTGRES_PASSWORD']) {
    if (!/^[a-fA-F0-9]{64}$/.test(env[key])) fail('INVALID_' + key);
  }
  const tokens = ['ADMIN_TOKEN', 'DATA_TOKEN', 'UPSTREAM_TOKEN', 'ALERT_TOKEN', 'CLIENT_TOKEN'].map(k => env[k]);
  if (new Set(tokens).size !== tokens.length) fail('TOKENS_MUST_BE_DISTINCT');
  for (const [key, fallback] of [['RG_GUARD_PORT', '8080'], ['RG_N8N_PORT', '5678']]) {
    env[key] ??= fallback;
    if (!/^\d{4,5}$/.test(env[key]) || Number(env[key]) < 1024 || Number(env[key]) > 65535) fail('INVALID_' + key);
  }
  if (env.RG_GUARD_PORT === env.RG_N8N_PORT) fail('PORTS_MUST_BE_DISTINCT');
  return env;
}

export async function environment(directory = root, create = false) {
  const path = join(directory, '.env');
  let created = false;
  try { const info = await lstat(path); if (!info.isFile() || info.isSymbolicLink()) fail('ENV_MUST_BE_REGULAR_FILE'); }
  catch (error) {
    if (error.code !== 'ENOENT') throw error;
    if (!create) fail('ENV_MISSING_RUN_START');
    const text = secretKeys.map(k => k + '=' + randomBytes(32).toString('hex')).join('\n') + '\n';
    try { await writeFile(path, text, { flag: 'wx', mode: 0o600 }); created = true; }
    catch (e) { if (e.code !== 'EEXIST') throw e; }
  }
  const env = validateEnvironment(parseEnv(await readFile(path, 'utf8')));
  if (process.platform !== 'win32') await chmod(path, 0o600);
  return { env, created };
}

export async function bundle(directory, env) {
  validateEnvironment(env);
  const definitions = [
    ['rgupstreamcred01', 'ReleaseGuard upstream', 'x-releaseguard-upstream', env.UPSTREAM_TOKEN],
    ['rgclientcred01', 'ReleaseGuard client', 'x-releaseguard-client', env.CLIENT_TOKEN],
    ['rgdatacred01', 'ReleaseGuard data', 'Authorization', 'Bearer ' + env.DATA_TOKEN],
    ['rgalertcred01', 'ReleaseGuard alerts', 'x-releaseguard-alert', env.ALERT_TOKEN],
  ];
  const credentials = definitions.map(([id, name, header, value]) => ({ id, name, type: 'httpHeaderAuth', data: { name: header, value } }));
  const hookCredential = { stable: credentials[0], candidate: credentials[0], gateway: credentials[1], alerts: credentials[3] };
  const workflows = [];
  for (const name of ['stable', 'candidate', 'alerts', 'gateway']) {
    const workflow = JSON.parse(await readFile(join(directory, 'workflows', name + '.json'), 'utf8'));
    for (const node of workflow.nodes) {
      let credential;
      if (node.type === 'n8n-nodes-base.webhook') credential = hookCredential[name];
      if (node.type === 'n8n-nodes-base.httpRequest') credential = credentials[2];
      if (credential) node.credentials = { httpHeaderAuth: { id: credential.id, name: credential.name } };
    }
    workflows.push(workflow);
  }
  const spec = JSON.parse(await readFile(join(directory, 'config/demo-release.json'), 'utf8'));
  const normalizedConfig = { ...spec.config, policy: policy(spec.config.policy) };
  const fingerprint = hash({ workflows, credentials, spec,
    persistentKeys: Object.fromEntries(secretKeys.map(k => [k, hash(env[k])])) });
  return { workflows, credentials, spec, normalizedConfig, fingerprint, encryptionKeyHash: hash(env.N8N_ENCRYPTION_KEY) };
}

function compose(project, env, args, input) {
  try {
    return execFileSync('docker', ['compose', '--project-name', project, '--env-file', join(root, '.env'),
      '-f', join(root, 'compose.yaml'), ...args], {
      cwd: root, env: { ...process.env, ...env }, input, encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'], timeout: 240000, maxBuffer: 4 * 1024 * 1024,
    });
  } catch (error) { fail(error.code === 'ENOENT' ? 'DOCKER_UNAVAILABLE' : 'DOCKER_COMPOSE_FAILED'); }
}

async function ready(url) {
  const deadline = Date.now() + 180000;
  while (Date.now() < deadline) {
    try { if ((await fetch(url, { redirect: 'error', signal: AbortSignal.timeout(3000) })).ok) return; } catch {}
    await new Promise(r => setTimeout(r, 1000));
  }
  fail('SERVICE_NOT_READY');
}

async function jsonRequest(url, { token, data, headers = {}, method = data ? 'POST' : 'GET' } = {}) {
  const response = await fetch(url, { method, redirect: 'error', signal: AbortSignal.timeout(30000),
    headers: { 'content-type': 'application/json', ...(token ? { authorization: 'Bearer ' + token } : {}), ...headers },
    body: data === undefined ? undefined : JSON.stringify(data) });
  let body; try { body = await response.json(); } catch { fail('UNEXPECTED_SERVICE_RESPONSE'); }
  return { status: response.status, body };
}

function cohortKey(env, id, pct, arm) {
  const prefix = 'setup-' + randomUUID();
  for (let i = 0; i < 100000; i++) {
    const key = prefix + '-' + i;
    const h = createHmac('sha256', Buffer.from(env.RESPONSE_KEY_HEX, 'hex')).update('route:' + id + ':' + key).digest('hex');
    if ((parseInt(h.slice(0, 8), 16) / 0x100000000 * 100 < pct) === (arm === 'candidate')) return key;
  }
  fail('COHORT_SELECTION_FAILED');
}

async function smoke(env, spec, release, n8n) {
  const tests = [];
  const arms = release.candidatePct === 0 ? ['stable'] : release.candidatePct === 100 ? ['candidate'] : ['stable', 'candidate'];
  for (const arm of arms) {
    const requestId = cohortKey(env, spec.id, release.candidatePct, arm);
    const deadline = Date.now() + 30000;
    let response;
    do {
      response = await jsonRequest(n8n + '/webhook/releaseguard', { data: { leadId: 'SETUP-SMOKE', score: 81 },
        headers: { 'x-releaseguard-client': env.CLIENT_TOKEN, 'x-request-id': requestId } });
      // The readiness endpoint can precede production webhook registration after
      // CLI publication. Retry only a missing webhook, with the same request ID.
      if (response.status !== 404 || Date.now() >= deadline) break;
      await new Promise(r => setTimeout(r, 1000));
    } while (true);
    const b = response.body;
    if (response.status !== 200 || b.servedBy !== arm || b.fallback !== false || b.result?.leadId !== 'SETUP-SMOKE'
      || b.result?.score !== 81 || b.result?.priority !== 'HIGH' || b.result?.engine !== arm) fail('GATEWAY_' + arm.toUpperCase() + '_SMOKE_FAILED');
    tests.push(arm + ' through authenticated Gateway and guarded service');
  }
  return tests;
}

function options(argv) {
  const command = argv.shift();
  if (!['start', 'install'].includes(command)) fail('USAGE_START_OR_INSTALL');
  let project = 'releaseguard-n8n';
  if (argv.length) {
    if (argv.length !== 2 || argv[0] !== '--project' || !/^[a-z0-9][a-z0-9_-]{0,62}$/.test(argv[1])) fail('INVALID_PROJECT_OPTION');
    project = argv[1];
  }
  return { command, project };
}

export async function setup(argv) {
  const { command, project } = options([...argv]);
  const { env, created } = await environment(root, command === 'start');
  const api = 'http://127.0.0.1:' + env.RG_GUARD_PORT, n8n = 'http://127.0.0.1:' + env.RG_N8N_PORT;
  compose(project, env, ['version']);
  if (command === 'start') {
    compose(project, env, ['up', '-d', '--build']);
    await ready(n8n + '/healthz/readiness'); await ready(api + '/readyz');
    return { verdict: 'STACK_STARTED', keys: created ? 'CREATED' : 'PRESERVED', n8n, dashboard: api,
      next: 'Create the n8n owner in the browser, then run: node scripts/setup.mjs install' + (project === 'releaseguard-n8n' ? '' : ' --project ' + project) };
  }
  const services = compose(project, env, ['ps', '--status', 'running', '--services']).trim().split(/\r?\n/);
  if (!['n8n', 'postgres', 'releaseguard'].every(s => services.includes(s))) fail('STACK_NOT_RUNNING_RUN_START');
  await ready(n8n + '/healthz/readiness'); await ready(api + '/readyz');
  const input = await bundle(root, env);
  const registered = await jsonRequest(api + '/v1/releases/' + input.spec.id, { token: env.ADMIN_TOKEN });
  if (registered.status !== 200) fail('GUARD_ADMIN_AUTH_FAILED');
  if (registered.body.release && registered.body.release.configHash !== hash(input.normalizedConfig)) fail('EXISTING_RELEASE_CONFIG_CONFLICT');
  input.existingRelease = !!registered.body.release;
  const workerSource = await readFile(join(root, 'scripts/n8n-install-worker.cjs'), 'utf8');
  const worker = action => {
    const stdout = compose(project, env, ['exec', '-T', 'n8n', 'node', '-e', workerSource], JSON.stringify({ ...input, action }));
    let result; try { result = JSON.parse(stdout.trim()); } catch { fail('INSTALLER_WORKER_RESPONSE_INVALID'); }
    if (!result.ok) fail(result.error || 'N8N_INSTALL_FAILED');
    return result;
  };
  const result = worker('install');
  if (result.restartRequired) { compose(project, env, ['restart', 'n8n']); await ready(n8n + '/healthz/readiness'); }
  if (!registered.body.release) {
    const createdRelease = await jsonRequest(api + '/v1/releases', { token: env.ADMIN_TOKEN, data: input.spec });
    if (createdRelease.status !== 201) fail('RELEASE_REGISTRATION_FAILED');
  }
  const current = await jsonRequest(api + '/v1/releases/' + input.spec.id, { token: env.ADMIN_TOKEN });
  const release = current.body.release;
  if (current.status !== 200 || !release || current.body.localFence) fail('RELEASE_STATE_UNCONFIRMED');
  const tests = await smoke(env, input.spec, release, n8n);
  worker('confirm');
  return { verdict: release.status === 'RUNNING' ? 'READY_FOR_CANARY' : 'INSTALLATION_VERIFIED',
    installation: result.initial ? 'CREATED' : 'VERIFIED', keys: 'PRESERVED', workflows: 4, credentials: 4,
    releaseId: release.id, releaseStatus: release.status, candidatePct: release.candidatePct,
    n8n, dashboard: api, tests, scope: 'Bundled local read-only demo; default production evidence gates remain unchanged.' };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { console.log(JSON.stringify(await setup(process.argv.slice(2)), null, 2)); }
  catch (error) { console.error(JSON.stringify({ verdict: 'BLOCKED', error: error.setupCode || 'SETUP_FAILED',
    next: 'See docs/SETUP.md for this error. Existing keys and database volumes are retained.' })); process.exitCode = 1; }
}
