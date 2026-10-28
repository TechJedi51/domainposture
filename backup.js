"use strict";

const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');
const { promisify } = require('util');
const scrypt = promisify(crypto.scrypt);
const gzip = promisify(zlib.gzip);
const gunzip = promisify(zlib.gunzip);
const AAD = Buffer.from('DomainPosture backup v1');
const MAX_BYTES = 64 * 1024 * 1024;
const FILES = new Set(['settings.json', 'secrets.json', 'domainposture-state.json', '.domainposture-secrets-key', 'parsedmarc/config.ini', 'logs/domainposture.log']);
const BACKUP_NAME = /^domainposture-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{3}Z-[a-f0-9]{8}\.dpbackup$/;

async function readPassword(filename) {
  if (!filename) throw new Error('Choose a separate backup password file in Settings → General.');
  const handle = await fs.open(filename, 'r');
  try {
    if ((await handle.stat()).size > 4096) throw new Error('Backup password file is too large.');
    const password = (await handle.readFile('utf8')).replace(/\r?\n$/, '');
    if (Buffer.byteLength(password) < 20 || Buffer.byteLength(password) > 1024) throw new Error('Use a backup password of 20 to 1024 bytes.');
    return password;
  } finally { await handle.close(); }
}

async function deriveKey(password, salt) {
  return scrypt(password, salt, 32, { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
}

async function encryptBackup(payload, password) {
  const raw = Buffer.from(JSON.stringify(payload));
  if (raw.length > MAX_BYTES) throw new Error('Application backup exceeds the 64 MiB export limit.');
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = await deriveKey(password, salt);
  try {
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    cipher.setAAD(AAD);
    const ciphertext = Buffer.concat([cipher.update(await gzip(raw)), cipher.final()]);
    return JSON.stringify({ format: 'domainposture-backup', version: 1, algorithm: 'aes-256-gcm', kdf: 'scrypt-N32768-r8-p1', salt: salt.toString('base64'), iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), ciphertext: ciphertext.toString('base64') }) + '\n';
  } finally { key.fill(0); }
}

async function decryptBackup(encoded, password) {
  const doc = JSON.parse(encoded);
  if (doc.format !== 'domainposture-backup' || doc.version !== 1 || doc.algorithm !== 'aes-256-gcm' || doc.kdf !== 'scrypt-N32768-r8-p1') throw new Error('Unsupported backup format.');
  const decode = (name, size) => {
    if (typeof doc[name] !== 'string') throw new Error('Invalid backup envelope.');
    const value = Buffer.from(doc[name], 'base64');
    if (size && value.length !== size) throw new Error('Invalid backup envelope.');
    return value;
  };
  const key = await deriveKey(password, decode('salt', 16));
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, decode('iv', 12));
    decipher.setAAD(AAD);
    decipher.setAuthTag(decode('tag', 16));
    const compressed = Buffer.concat([decipher.update(decode('ciphertext')), decipher.final()]);
    const payload = JSON.parse((await gunzip(compressed, { maxOutputLength: MAX_BYTES })).toString('utf8'));
    if (payload.schema_version !== 1 || !payload.files || typeof payload.files !== 'object' || Array.isArray(payload.files)) throw new Error('Invalid backup payload.');
    if (!Object.hasOwn(payload.files, 'settings.json')) throw new Error('Backup has no settings file.');
    for (const [name, contents] of Object.entries(payload.files)) {
      if (!FILES.has(name) || typeof contents !== 'string') throw new Error('Invalid backup file entry.');
    }
    return payload;
  } finally { key.fill(0); }
}

function normalizeBackupSettings(input = {}) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('Invalid backup settings.');
  const integer = (name, fallback, min, max) => {
    const value = input[name] === undefined ? fallback : input[name];
    if (!Number.isInteger(value) || value < min || value > max) throw new Error(`Invalid backup ${name}.`);
    return value;
  };
  if (input.enabled !== undefined && typeof input.enabled !== 'boolean') throw new Error('Invalid backup enabled setting.');
  if (input.password_file !== undefined && typeof input.password_file !== 'string') throw new Error('Invalid backup password file.');
  const passwordFile = (input.password_file || '').trim();
  if (passwordFile && (!path.isAbsolute(passwordFile) || passwordFile.includes('\0') || passwordFile.length > 4096)) throw new Error('Backup password file must be an absolute path on the application system.');
  const settings = { enabled: input.enabled === true, password_file: passwordFile, hour_utc: integer('hour_utc', 2, 0, 23), keep: integer('keep', 7, 1, 365) };
  if (settings.enabled && !settings.password_file) throw new Error('Choose a backup password file before enabling backups.');
  return settings;
}

function backupConfiguration(settings, directory = '/data/backups') {
  const backup = normalizeBackupSettings(settings);
  if (!backup.enabled) return null;
  return { directory, passwordFile: backup.password_file, hour: backup.hour_utc, retain: backup.keep };
}

async function createBackup({ directory, passwordFile, retain }, snapshot) {
  const password = await readPassword(passwordFile);
  const payload = await snapshot();
  const encrypted = await encryptBackup(payload, password);
  // Authenticate and validate before publishing or removing any older export.
  await decryptBackup(encrypted, password);
  await fs.mkdir(directory, { recursive: true, mode: 0o755 });
  const name = `domainposture-${new Date().toISOString().replace(/[:.]/g, '-')}-${crypto.randomBytes(4).toString('hex')}.dpbackup`;
  const filename = path.join(directory, name);
  const temporary = filename + '.tmp';
  try {
    await fs.writeFile(temporary, encrypted, { flag: 'wx', mode: 0o600 });
    // Only the encrypted export is readable by other backup accounts.
    await fs.chmod(temporary, 0o644);
    await fs.rename(temporary, filename);
  } finally { await fs.unlink(temporary).catch(error => { if (error.code !== 'ENOENT') throw error; }); }
  const previous = (await fs.readdir(directory)).filter(entry => BACKUP_NAME.test(entry) && entry !== name).sort().reverse();
  for (const entry of previous.slice(retain - 1)) await fs.unlink(path.join(directory, entry));
  return name;
}

function startBackupSchedule(configuration, snapshot, report, options = {}) {
  const now = options.now || (() => new Date());
  const schedule = options.setTimeout || setTimeout;
  const cancel = options.clearTimeout || clearTimeout;
  let timer;
  let stopped = false;
  let running = null;
  const run = () => {
    if (running) return running;
    running = createBackup(configuration, snapshot)
      .then(() => report('info', 'Encrypted application backup created'))
      .catch(() => report('error', 'Application backup failed; check the backup password file, source files, storage access, and free space.'))
      .finally(() => { running = null; });
    return running;
  };
  const arm = () => {
    if (stopped) return;
    const current = now();
    const next = new Date(current);
    next.setUTCHours(configuration.hour, 0, 0, 0);
    if (next <= current) next.setUTCDate(next.getUTCDate() + 1);
    timer = schedule(async () => { await run(); arm(); }, next - current);
    timer.unref?.();
  };
  // A startup export prevents an installation from waiting a whole day for its first backup.
  run().finally(arm);
  return { stop() { stopped = true; if (timer) cancel(timer); return running || Promise.resolve(); }, run };
}

async function recoverBackup(archive, passwordFile, output) {
  if ((await fs.stat(archive)).size > MAX_BYTES * 2) throw new Error('Backup file exceeds the recovery size limit.');
  const payload = await decryptBackup(await fs.readFile(archive, 'utf8'), await readPassword(passwordFile));
  // Refuse an existing destination; recovery never overwrites a live installation.
  await fs.mkdir(output, { mode: 0o700 });
  for (const [name, contents] of Object.entries(payload.files)) {
    const target = path.join(output, name);
    await fs.mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
    await fs.writeFile(target, Buffer.from(contents, 'base64'), { flag: 'wx', mode: 0o600 });
  }
  return payload;
}

module.exports = { readPassword, encryptBackup, decryptBackup, normalizeBackupSettings, backupConfiguration, createBackup, startBackupSchedule, recoverBackup };

if (require.main === module) {
  const [command, archive, passwordFile, output] = process.argv.slice(2);
  if (command !== 'recover' || !archive || !passwordFile || !output || process.argv.length !== 6) {
    console.error('Usage: node backup.js recover ARCHIVE PASSWORD_FILE NEW_OUTPUT_DIRECTORY');
    process.exitCode = 1;
  } else {
    recoverBackup(archive, passwordFile, output)
      .then(() => console.log('Backup authenticated and extracted. Review files before restoring to a stopped application.'))
      .catch(() => { console.error('Recovery failed. Check the archive, password, and destination. Output may be incomplete; do not use it as a live installation.'); process.exitCode = 1; });
  }
}
