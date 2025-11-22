const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

const SQLITE_HEADER = Buffer.from('SQLite format 3\0', 'utf8');

function ensureDirectory(target) {
  if (!fs.existsSync(target)) {
    fs.mkdirSync(target, { recursive: true });
  }
}

function encryptBuffer(plainBuffer, saltSeed) {
  const salt = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const key = deriveKey(saltSeed, salt);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plainBuffer), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { salt, iv, ciphertext, tag };
}

function decryptBuffer(payload, saltSeed) {
  const key = deriveKey(saltSeed, payload.salt);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, payload.iv);
  decipher.setAuthTag(payload.tag);
  return Buffer.concat([decipher.update(payload.ciphertext), decipher.final()]);
}

function deriveKey(seed, salt) {
  const base = crypto.createHash('sha3-512').update(seed).digest();
  return crypto.createHash('sha3-512').update(base).update(salt).digest().subarray(0, 32);
}

function readVaultFile(filePath, seed) {
  if (!fs.existsSync(filePath)) {
    return null;
  }
  const buffer = fs.readFileSync(filePath);
  if (buffer.length < SQLITE_HEADER.length + 60) {
    return null;
  }
  const header = buffer.subarray(0, SQLITE_HEADER.length);
  if (!header.equals(SQLITE_HEADER)) {
    throw new Error('Quantum vault corrupted');
  }
  const salt = buffer.subarray(SQLITE_HEADER.length, SQLITE_HEADER.length + 32);
  const iv = buffer.subarray(SQLITE_HEADER.length + 32, SQLITE_HEADER.length + 44);
  const tag = buffer.subarray(SQLITE_HEADER.length + 44, SQLITE_HEADER.length + 60);
  const ciphertext = buffer.subarray(SQLITE_HEADER.length + 60);
  const decrypted = decryptBuffer({ salt, iv, ciphertext, tag }, seed);
  return JSON.parse(decrypted.toString('utf8'));
}

function writeVaultFile(filePath, seed, payload) {
  const data = Buffer.from(JSON.stringify(payload), 'utf8');
  const encrypted = encryptBuffer(data, seed);
  const buffer = Buffer.concat([SQLITE_HEADER, encrypted.salt, encrypted.iv, encrypted.tag, encrypted.ciphertext]);
  fs.writeFileSync(filePath, buffer);
}

class QuantumProfileVault {
  constructor(userRoot, machineRoot) {
    this.userRoot = userRoot;
    this.machineRoot = machineRoot;
    this.userSeed = `${os.hostname()}|${os.userInfo().username}|${os.arch()}|${process.env.LOGONSERVER ?? ''}`;
    this.machineSeed = `${os.hostname()}|${os.arch()}|${process.env.COMPUTERNAME ?? ''}|${process.env.PROCESSOR_IDENTIFIER ?? ''}`;
    this.userVaultPath = path.join(this.userRoot, 'profiles');
    this.machineVaultPath = path.join(this.machineRoot, 'subscription');
    ensureDirectory(this.userVaultPath);
    ensureDirectory(this.machineVaultPath);
    this.userFile = path.join(this.userVaultPath, 'client-profile.sqlite');
    this.subscriptionFile = path.join(this.machineVaultPath, 'subscription.sqlite');
  }

  loadUserProfile() {
    return readVaultFile(this.userFile, this.userSeed);
  }

  saveUserProfile(profile) {
    const payload = {
      schema: 1,
      updatedAt: new Date().toISOString(),
      profile
    };
    writeVaultFile(this.userFile, this.userSeed, payload);
  }

  loadSubscription() {
    return readVaultFile(this.subscriptionFile, this.machineSeed);
  }

  saveSubscription(subscription) {
    const payload = {
      schema: 1,
      updatedAt: new Date().toISOString(),
      subscription
    };
    writeVaultFile(this.subscriptionFile, this.machineSeed, payload);
  }
}

module.exports = { QuantumProfileVault };
