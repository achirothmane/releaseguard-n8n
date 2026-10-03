import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { environment, validateEnvironment, bundle, secretKeys } from '../scripts/setup.mjs';

const root = resolve(new URL('..', import.meta.url).pathname);
async function fresh(t) {
  await mkdir(join(root, 'tmp'), { recursive: true });
  const directory = await mkdtemp(join(root, 'tmp', 'setup-unit-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  return directory;
}
test('first start generates private persistent keys; rerun preserves every byte', async t => {
  const directory = await fresh(t);
  const first = await environment(directory, true), saved = await readFile(join(directory, '.env'));
  assert.equal(first.created, true);
  assert.equal(new Set(secretKeys.map(k => first.env[k])).size, secretKeys.length);
  const repeated = await environment(directory, true);
  assert.equal(repeated.created, false);
  assert.deepEqual(await readFile(join(directory, '.env')), saved);
  assert.equal((await stat(join(directory, '.env'))).mode & 0o777, 0o600);
});
test('install never creates a missing key file', async t => {
  const directory = await fresh(t);
  await assert.rejects(environment(directory), /ENV_MISSING_RUN_START/);
  await assert.rejects(readFile(join(directory, '.env')), { code: 'ENOENT' });
});
test('invalid existing keys block rather than silently regenerate', async t => {
  const directory = await fresh(t), text = 'ADMIN_TOKEN=bad-existing-key\n';
  await writeFile(join(directory, '.env'), text);
  await assert.rejects(environment(directory, true), /INVALID_/);
  assert.equal(await readFile(join(directory, '.env'), 'utf8'), text);
});
test('setup rejects a symlinked key file', async t => {
  const directory = await fresh(t);
  await writeFile(join(directory, 'other'), 'must-not-be-used');
  await symlink(join(directory, 'other'), join(directory, '.env'));
  await assert.rejects(environment(directory, true), /ENV_MUST_BE_REGULAR_FILE/);
});
test('credential roles cannot share a token, and errors do not disclose values', async t => {
  const { env } = await environment(await fresh(t), true);
  env.CLIENT_TOKEN = env.DATA_TOKEN;
  assert.throws(() => validateEnvironment(env), /TOKENS_MUST_BE_DISTINCT/);
  const invalid = 'secret$value-that-must-never-be-printed';
  env.ADMIN_TOKEN = invalid;
  try { validateEnvironment(env); assert.fail('expected rejection'); }
  catch (error) { assert.equal(error.message, 'INVALID_ADMIN_TOKEN'); assert.ok(!error.message.includes(invalid)); }
});
test('ambiguous database passwords and conflicting ports block before Compose', async t => {
  const { env } = await environment(await fresh(t), true);
  assert.throws(() => validateEnvironment({ ...env, POSTGRES_PASSWORD: 'p'.repeat(40) + '@' }), /INVALID_POSTGRES_PASSWORD/);
  assert.throws(() => validateEnvironment({ ...env, RG_GUARD_PORT: '5678' }), /PORTS_MUST_BE_DISTINCT/);
  assert.throws(() => validateEnvironment({ ...env, RG_N8N_PORT: '70000' }), /INVALID_RG_N8N_PORT/);
});
test('prepared workflows use credential references and retain no plaintext secrets', async t => {
  const { env } = await environment(await fresh(t), true), prepared = await bundle(root, env);
  const text = JSON.stringify(prepared.workflows);
  for (const key of secretKeys) assert.ok(!text.includes(env[key]), key);
  for (const w of prepared.workflows) {
    const hook = w.nodes.find(n => n.type === 'n8n-nodes-base.webhook');
    assert.equal(hook.parameters.authentication, 'headerAuth');
    assert.ok(prepared.credentials.some(c => c.id === hook.credentials.httpHeaderAuth.id));
  }
  const gateway = prepared.workflows.find(w => w.id === 'rg-gateway');
  const ingress = gateway.nodes.find(n => n.type === 'n8n-nodes-base.webhook').credentials.httpHeaderAuth.id;
  const data = gateway.nodes.find(n => n.type === 'n8n-nodes-base.httpRequest').credentials.httpHeaderAuth.id;
  assert.notEqual(ingress, data);
  assert.equal(prepared.credentials.find(c => c.id === data).data.value, 'Bearer ' + env.DATA_TOKEN);
});
test('resume identity binds persistent keys and the workflow definitions', async t => {
  const { env } = await environment(await fresh(t), true);
  const first = await bundle(root, env), again = await bundle(root, env);
  assert.equal(first.fingerprint, again.fingerprint);
  const rotated = await bundle(root, { ...env, UPSTREAM_TOKEN: 'e'.repeat(64) });
  assert.notEqual(first.fingerprint, rotated.fingerprint);
});
