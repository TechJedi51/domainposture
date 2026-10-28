'use strict';
const assert = require('assert');
const fs = require('fs').promises;
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const backup = require('../backup');
const app = require('../server');

async function run() {
  const temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'domainposture-backup-test-'));
  try {
    const password = 'test-only-independent-backup-password';
    const passwordFile = path.join(temporary, 'password');
    await fs.writeFile(passwordFile, password + '\n', { mode: 0o600 });
    const payload = { schema_version: 1, created_at: new Date().toISOString(), files: {
      'settings.json': Buffer.from('{"domain":"example.test"}').toString('base64'),
      'secrets.json': Buffer.from('saved-secret-fixture').toString('base64'),
      '.domainposture-secrets-key': Buffer.from('recovery-key-fixture').toString('base64'),
      'parsedmarc/config.ini': Buffer.from('password=private-fixture').toString('base64'),
      'logs/domainposture.log': Buffer.from('diagnostic-fixture').toString('base64')
    }, missing: ['domainposture-state.json'], log_truncated: false };
    assert.strictEqual(await backup.readPassword(passwordFile), password);
    assert.strictEqual(backup.backupConfiguration({}), null);
    assert.deepStrictEqual(app.normalizeSettings({}).backups, { enabled: false, password_file: '', hour_utc: 2, keep: 7 });
    assert.strictEqual(backup.backupConfiguration({ enabled: true }).passwordFile, '/data/.domainposture-backup-password');
    const inputSettings = { enabled: true, password_file: passwordFile };
    const configuration = backup.backupConfiguration(inputSettings);
    assert.strictEqual(configuration.hour, 2);
    assert.strictEqual(configuration.retain, 7);
    assert.deepStrictEqual(app.normalizeSettings({ backups: inputSettings }).backups, { ...inputSettings, hour_utc: 2, keep: 7 });
    for (const [name, value] of [['hour_utc', 24], ['keep', 0], ['keep', 2.5], ['enabled', 'false'], ['password_file', 'relative/path']]) {
      assert.throws(() => backup.backupConfiguration({ ...inputSettings, [name]: value }));
    }
    assert.strictEqual(backup.backupConfiguration({ DOMAINPOSTURE_BACKUP_ENABLED: 'true' }), null, 'legacy environment keys do not enable backups');
    const encrypted = await backup.encryptBackup(payload, password);
    assert.doesNotMatch(encrypted, /saved-secret-fixture|private-fixture|recovery-key-fixture|example.test/);
    assert.deepStrictEqual(await backup.decryptBackup(encrypted, password), payload);
    assert.notStrictEqual(await backup.encryptBackup(payload, password), encrypted);
    await assert.rejects(() => backup.decryptBackup(encrypted, 'wrong-password'));
    const tampered = JSON.parse(encrypted);
    const ciphertext = Buffer.from(tampered.ciphertext, 'base64');
    ciphertext[0] ^= 1;
    tampered.ciphertext = ciphertext.toString('base64');
    await assert.rejects(() => backup.decryptBackup(JSON.stringify(tampered), password));
    const malicious = await backup.encryptBackup({ ...payload, files: { ...payload.files, '../escape': 'eA==' } }, password);
    await assert.rejects(() => backup.decryptBackup(malicious, password), /Invalid backup file/);
    const directory = path.join(temporary, 'backups');
    const settings = { directory, passwordFile, retain: 2 };
    for (let i = 0; i < 3; i++) await backup.createBackup(settings, async () => payload);
    const names = await fs.readdir(directory);
    assert.strictEqual(names.length, 2);
    assert(names.every(name => name.endsWith('.dpbackup')));
    let archive = path.join(directory, names[0]);
    if (process.platform !== 'win32') {
      assert.strictEqual((await fs.stat(archive)).mode & 0o777, 0o644);
      assert.strictEqual((await fs.stat(directory)).mode & 0o777, 0o755);
    }
    await fs.writeFile(path.join(directory, 'unrelated.txt'), 'keep');
    await assert.rejects(() => backup.createBackup(settings, async () => { throw new Error('source failed'); }), /source failed/);
    assert.strictEqual((await fs.readdir(directory)).length, 3);
    await backup.createBackup(settings, async () => payload);
    assert.strictEqual(await fs.readFile(path.join(directory, 'unrelated.txt'), 'utf8'), 'keep');
    archive = path.join(directory, (await fs.readdir(directory)).find(name => name.endsWith('.dpbackup')));
    const output = path.join(temporary, 'restore');
    assert.deepStrictEqual(await backup.recoverBackup(archive, passwordFile, output), payload);
    assert.strictEqual(await fs.readFile(path.join(output, 'parsedmarc/config.ini'), 'utf8'), 'password=private-fixture');
    if (process.platform !== 'win32') assert.strictEqual((await fs.stat(path.join(output, 'settings.json'))).mode & 0o777, 0o600);
    await assert.rejects(() => backup.recoverBackup(archive, passwordFile, output), /EEXIST/);
    const badPassword = path.join(temporary, 'bad-password');
    await fs.writeFile(badPassword, 'another-long-but-incorrect-password');
    const rejectedOutput = path.join(temporary, 'wrong-restore');
    await assert.rejects(() => backup.recoverBackup(archive, badPassword, rejectedOutput));
    await assert.rejects(() => fs.stat(rejectedOutput), /ENOENT/);
    const cliOutput = path.join(temporary, 'cli-restore');
    const cli = spawnSync(process.execPath, [path.join(__dirname, '../backup.js'), 'recover', archive, passwordFile, cliOutput], { encoding: 'utf8' });
    assert.strictEqual(cli.status, 0, cli.stderr);
    assert.strictEqual(await fs.readFile(path.join(cliOutput, 'settings.json'), 'utf8'), '{"domain":"example.test"}');
    await fs.writeFile(badPassword, 'short');
    await assert.rejects(() => backup.readPassword(badPassword), /20 to 1024/);

    // Exercise the real application's snapshot reader with isolated fixture files.
    const source = path.join(temporary, 'source');
    await fs.mkdir(path.join(source, 'parsedmarc'), { recursive: true });
    const key = Buffer.alloc(32, 17);
    const encryptedSecrets = app.encryptSecrets({ imap_password: 'fixture-mailbox-password' }, key);
    const sourceFiles = {
      'settings.json': '{"monitored_domains":["example.test"]}',
      'secrets.json': JSON.stringify(encryptedSecrets),
      'domainposture-state.json': '{"certificates":{}}',
      'parsedmarc/config.ini': 'password=fixture-mailbox-password',
      '.domainposture-secrets-key': key.toString('base64') + '\n',
      'domainposture.log': 'x'.repeat(1024 * 1024 + 100)
    };
    for (const [name, contents] of Object.entries(sourceFiles)) await fs.writeFile(path.join(source, name), contents, { mode: 0o600 });
    const snapshotEnvironment = {
      ...process.env,
      DOMAINPOSTURE_SETTINGS_FILE: path.join(source, 'settings.json'),
      DOMAINPOSTURE_SECRETS_FILE: path.join(source, 'secrets.json'),
      DOMAINPOSTURE_STATE_PATH: path.join(source, 'domainposture-state.json'),
      PARSEDMARC_CONFIG_PATH: path.join(source, 'parsedmarc/config.ini'),
      DOMAINPOSTURE_MANAGED_SECRETS_KEY_FILE: path.join(source, '.domainposture-secrets-key'),
      DOMAINPOSTURE_LOG_PATH: path.join(source, 'domainposture.log')
    };
    delete snapshotEnvironment.DOMAINPOSTURE_SECRETS_KEY;
    delete snapshotEnvironment.DOMAINPOSTURE_SECRETS_KEY_FILE;
    const snapshotScript = `require(${JSON.stringify(path.join(__dirname, '../server.js'))}).captureApplicationBackup().then(value => process.stdout.write(JSON.stringify(value))).catch(() => { process.exitCode = 1; });`;
    const capture = environment => spawnSync(process.execPath, ['-e', snapshotScript], { env: environment, encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 });
    const captured = capture(snapshotEnvironment);
    assert.strictEqual(captured.status, 0, captured.stderr);
    const snapshot = JSON.parse(captured.stdout);
    assert.strictEqual(snapshot.log_truncated, true);
    assert.strictEqual(Buffer.from(snapshot.files['logs/domainposture.log'], 'base64').length, 1024 * 1024);
    assert.strictEqual(Buffer.from(snapshot.files['.domainposture-secrets-key'], 'base64').toString().trim(), key.toString('base64'));
    assert.deepStrictEqual(app.decryptSecrets(JSON.parse(Buffer.from(snapshot.files['secrets.json'], 'base64')), key), { imap_password: 'fixture-mailbox-password' });
    if (process.platform !== 'win32') assert.strictEqual((await fs.stat(path.join(source, 'settings.json'))).mode & 0o777, 0o600);
    assert.strictEqual(capture({ ...snapshotEnvironment, DOMAINPOSTURE_SECRETS_KEY: Buffer.alloc(32, 18).toString('base64') }).status, 1, 'mismatched recovery key must fail');
    const externalKey = path.join(source, 'external-key');
    await fs.writeFile(externalKey, key.toString('base64'), { mode: 0o600 });
    assert.strictEqual(capture({ ...snapshotEnvironment, DOMAINPOSTURE_SECRETS_KEY_FILE: externalKey }).status, 0);
    await fs.unlink(path.join(source, 'domainposture.log'));
    const withoutLog = JSON.parse(capture(snapshotEnvironment).stdout);
    assert(withoutLog.missing.includes('logs/domainposture.log'));
    await fs.unlink(path.join(source, 'settings.json'));
    assert.strictEqual(capture(snapshotEnvironment).status, 1, 'missing required settings must fail');

    const events = [];
    let release;
    const barrier = new Promise(resolve => { release = resolve; });
    const first = app.withPersistenceLock(async () => { events.push('write-start'); await barrier; events.push('write-end'); });
    const second = app.withPersistenceLock(async () => { events.push('snapshot'); });
    await new Promise(resolve => setImmediate(resolve));
    assert.deepStrictEqual(events, ['write-start']);
    release();
    await Promise.all([first, second]);
    assert.deepStrictEqual(events, ['write-start', 'write-end', 'snapshot']);
    await assert.rejects(app.withPersistenceLock(async () => { throw new Error('write failed'); }), /write failed/);
    assert.strictEqual(await app.withPersistenceLock(async () => 'queue recovered'), 'queue recovered');

    let scheduled;
    let reported = 0;
    const schedule = backup.startBackupSchedule(settings.hour === undefined ? { ...settings, hour: 2 } : settings, async () => payload, () => { reported++; }, {
      now: () => new Date('2026-10-28T01:00:00Z'),
      setTimeout: (callback, milliseconds) => { scheduled = { callback, milliseconds }; return { unref() {} }; },
      clearTimeout: () => { scheduled = null; }
    });
    await schedule.run();
    await new Promise(resolve => setImmediate(resolve));
    assert.strictEqual(reported, 1, 'concurrent startup/manual calls share one export');
    assert.strictEqual(scheduled.milliseconds, 60 * 60 * 1000);
    await scheduled.callback();
    assert.strictEqual(reported, 2);
    schedule.stop();
    assert.strictEqual(scheduled, null);
    console.log('Backup tests passed');
  } finally { await fs.rm(temporary, { recursive: true, force: true }); }
}
run().catch(error => { console.error(error); process.exitCode = 1; });
