'use strict';
const assert = require('assert');
const fs = require('fs').promises;
const path = require('path');
const os = require('os');
const net = require('net');
const { spawn } = require('child_process');
const { once } = require('events');
const app = require('../server');
const backup = require('../backup');

async function waitFor(check) {
  const deadline = Date.now() + 10000;
  while (Date.now() < deadline) {
    const value = await check();
    if (value) return value;
    await new Promise(resolve => setTimeout(resolve, 25));
  }
  throw new Error('Timed out waiting for the application test.');
}

async function run() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'domainposture-backup-settings-'));
  const reservation = net.createServer();
  await new Promise((resolve, reject) => { reservation.once('error', reject); reservation.listen(0, '127.0.0.1', resolve); });
  const port = reservation.address().port;
  await new Promise(resolve => reservation.close(resolve));
  const settingsFile = path.join(root, 'settings.json');
  const passwordFile = path.join(root, 'separate-password');
  const directory = path.join(root, 'backups');
  await fs.writeFile(passwordFile, 'fixture-only-separate-backup-password', { mode: 0o600 });
  await fs.writeFile(settingsFile, JSON.stringify(app.normalizeSettings({ monitored_domains: ['example.test'], report_source: 'disabled' })), { mode: 0o600 });
  const environment = {
    ...process.env, PORT: String(port), DEMO_MODE: 'true', SERVICE_LOGS_ENABLED: 'false',
    DOMAINPOSTURE_SETTINGS_FILE: settingsFile,
    DOMAINPOSTURE_SECRETS_FILE: path.join(root, 'secrets.json'),
    DOMAINPOSTURE_STATE_PATH: path.join(root, 'state.json'),
    DOMAINPOSTURE_SECRETS_KEY: Buffer.alloc(32, 21).toString('base64'),
    PARSEDMARC_CONFIG_PATH: path.join(root, 'parsedmarc/config.ini'),
    DOMAINPOSTURE_LOG_PATH: path.join(root, 'missing.log'),
    DOMAINPOSTURE_BACKUP_DIR: directory,
    DOMAINPOSTURE_MANAGED_BACKUP_PASSWORD_FILE: path.join(root, '.domainposture-backup-password'),
    // Legacy environment controls must not override saved settings.
    DOMAINPOSTURE_BACKUP_ENABLED: 'true', DOMAINPOSTURE_BACKUP_PASSWORD_FILE: passwordFile,
    DOMAINPOSTURE_BACKUP_HOUR_UTC: '23', DOMAINPOSTURE_BACKUP_KEEP: '99'
  };
  let output = '';
  let child;
  const launch = async () => {
    output = '';
    child = spawn(process.execPath, [path.join(__dirname, '../server.js')], { env: environment, stdio: ['ignore', 'pipe', 'pipe'] });
    child.stdout.on('data', data => { output += data; });
    child.stderr.on('data', data => { output += data; });
    await waitFor(async () => {
      if (child.exitCode !== null) throw new Error('Application exited during test startup.');
      return output.includes('listening on');
    });
  };
  const stop = async () => {
    if (!child || child.exitCode !== null) return;
    const exited = once(child, 'exit');
    child.kill();
    await exited;
  };
  const base = `http://127.0.0.1:${port}`;
  const get = async () => (await fetch(base + '/api/settings')).json();
  const save = async value => {
    const response = await fetch(base + '/api/settings', { method: 'PUT', headers: { 'content-type': 'application/json', origin: base }, body: JSON.stringify(value) });
    return { status: response.status, body: await response.json() };
  };
  const exports = async () => (await fs.readdir(directory).catch(error => { if (error.code === 'ENOENT') return []; throw error; })).filter(name => name.endsWith('.dpbackup'));
  try {
    await launch();
    let settings = await get();
    assert.deepStrictEqual(settings.backups, { enabled: false, password_file: '', hour_utc: 2, keep: 7 });
    assert.deepStrictEqual(await exports(), []);
    const page = await (await fetch(base + '/')).text();
    const general = page.slice(page.indexOf('id="settings-panel-general"'), page.indexOf('class="settings-actions"'));
    for (const id of ['backup-enabled', 'backup-password-file', 'backup-hour-utc', 'backup-keep']) assert(general.includes(`id="${id}"`));
    let result = await save({ ...settings, backups: { enabled: true, password_file: path.join(root, 'absent'), hour_utc: 2, keep: 3 } });
    assert.strictEqual(result.status, 400);
    assert.strictEqual((await get()).backups.enabled, false);
    const hour = (new Date().getUTCHours() + 2) % 24;
    result = await save({ ...settings, backups: { enabled: true, password_file: passwordFile, hour_utc: hour, keep: 3 } });
    assert.strictEqual(result.status, 200, JSON.stringify(result.body));
    settings = result.body;
    await waitFor(async () => (await exports()).length === 1);
    assert.deepStrictEqual((await get()).backups, settings.backups);
    assert.deepStrictEqual(JSON.parse(await fs.readFile(settingsFile, 'utf8')).backups, settings.backups);
    const first = await exports();
    result = await save({ ...settings, report_days: 8 });
    assert.strictEqual(result.status, 200);
    settings = result.body;
    assert.deepStrictEqual(await exports(), first, 'unrelated save does not trigger an export');
    result = await save({ ...settings, backups: { ...settings.backups, hour_utc: (hour + 1) % 24 } });
    assert.strictEqual(result.status, 200);
    settings = result.body;
    await waitFor(async () => (await exports()).length === 2);
    await stop();
    await launch();
    await waitFor(async () => (await exports()).length === 3);
    assert.strictEqual((await get()).backups.hour_utc, (hour + 1) % 24);
    result = await save({ ...settings, backups: { ...settings.backups, enabled: false } });
    assert.strictEqual(result.status, 200);
    await stop();
    await launch();
    assert.strictEqual((await get()).backups.enabled, false);
    assert.strictEqual((await exports()).length, 3, 'disabled settings survive restart');
    // Existing external-password deployments remain read-only to management actions.
    let response = await fetch(base + '/api/backup-password', { method: 'POST', headers: { origin: base } });
    assert.strictEqual(response.status, 409);
    result = await save({ ...(await get()), backups: { ...(await get()).backups, enabled: false, password_file: '' } });
    assert.strictEqual(result.status, 200);
    assert.strictEqual((await get()).backup_password.can_generate, true);
    response = await fetch(base + '/api/backup-password', { method: 'POST', headers: { origin: 'https://untrusted.example' } });
    assert.strictEqual(response.status, 403);
    response = await fetch(base + '/api/backup-password', { method: 'POST', headers: { origin: base } });
    assert.strictEqual(response.status, 201);
    const generated = await response.json();
    assert.strictEqual(Buffer.from(generated.password, 'base64').length, 32);
    const managedFile = path.join(root, '.domainposture-backup-password');
    assert.strictEqual((await fs.readFile(managedFile, 'utf8')).trim(), generated.password);
    if (process.platform !== 'win32') assert.strictEqual((await fs.stat(managedFile)).mode & 0o777, 0o600);
    settings = await get();
    assert.strictEqual(settings.backup_password.source, 'managed');
    assert.strictEqual(settings.backup_password.can_rotate, true);
    assert(!JSON.stringify(settings).includes(generated.password));
    assert.strictEqual(settings.backups.enabled, false, 'creation does not enable exports');
    response = await fetch(base + '/api/backup-password', { method: 'POST', headers: { origin: base } });
    assert.strictEqual(response.status, 409, 'duplicate creation never replaces the password');
    assert.strictEqual((await fs.readFile(managedFile, 'utf8')).trim(), generated.password);
    const beforeManaged = await exports();
    result = await save({ ...settings, backups: { ...settings.backups, enabled: true } });
    assert.strictEqual(result.status, 200);
    const managedName = await waitFor(async () => (await exports()).find(name => !beforeManaged.includes(name)));
    const originalArchive = await fs.readFile(path.join(directory, managedName), 'utf8');
    const originalPayload = await backup.decryptBackup(originalArchive, generated.password);
    assert(!JSON.stringify(originalPayload).includes(generated.password));
    assert(!Object.hasOwn(originalPayload.files, '.domainposture-backup-password'));
    await stop();
    await launch();
    assert.strictEqual((await get()).backup_password.source, 'managed');
    // Ensure the startup export has completed before checking rotation.
    await waitFor(async () => output.includes('Encrypted application backup created'));
    const beforeRotate = await exports();
    response = await fetch(base + '/api/backup-password/rotate', { method: 'POST', headers: { origin: base } });
    assert.strictEqual(response.status, 200);
    const rotated = await response.json();
    assert.notStrictEqual(rotated.password, generated.password);
    assert.strictEqual((await fs.readFile(managedFile, 'utf8')).trim(), rotated.password);
    assert(!JSON.stringify(await get()).includes(rotated.password));
    const rotatedName = await waitFor(async () => (await exports()).find(name => !beforeRotate.includes(name)));
    const rotatedArchive = await fs.readFile(path.join(directory, rotatedName), 'utf8');
    await backup.decryptBackup(rotatedArchive, rotated.password);
    await assert.rejects(() => backup.decryptBackup(rotatedArchive, generated.password));
    await backup.decryptBackup(originalArchive, generated.password);
    await assert.rejects(() => backup.decryptBackup(originalArchive, rotated.password));
    assert(general.includes('Remember to save in 1Password.'));
    for (const id of ['create-backup-password', 'rotate-backup-password', 'backup-password-dialog', 'generated-backup-password']) assert(page.includes(`id="${id}"`));
    console.log('Backup Settings API tests passed');
  } finally {
    await stop();
    await fs.rm(root, { recursive: true, force: true });
  }
}
run().catch(error => { console.error(error); process.exitCode = 1; });
