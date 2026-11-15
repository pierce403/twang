import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createCipheriv, createDecipheriv, createHmac, diffieHellman, generateKeyPairSync, hkdfSync } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { generateProvisioningKeypair, identityPublicKey, decryptProvisioningEnvelope,
  encryptDeviceName, generateRegistrationKeys } from '../app/link-crypto.mjs';

const signal = raw => new Uint8Array(Buffer.concat([Buffer.from([5]), raw]));
async function envelopeFixture(plaintext = Buffer.from('authenticated provisioning payload\0\xff', 'binary')) {
  const receiver = generateKeyPairSync('x25519');
  const sender = generateKeyPairSync('x25519');
  const privateKey = await crypto.subtle.importKey('pkcs8', receiver.privateKey.export({ format: 'der', type: 'pkcs8' }), 'X25519', false, ['deriveBits']);
  const publicKey = signal(sender.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32));
  const secret = diffieHellman({ privateKey: sender.privateKey, publicKey: receiver.publicKey });
  const keys = Buffer.from(hkdfSync('sha256', secret, Buffer.alloc(32), Buffer.from('TextSecure Provisioning Message'), 64));
  const iv = Buffer.from('00112233445566778899aabbccddeeff', 'hex');
  const cipher = createCipheriv('aes-256-cbc', keys.subarray(0, 32), iv);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authenticated = Buffer.concat([Buffer.from([1]), iv, encrypted]);
  const body = new Uint8Array(Buffer.concat([authenticated, createHmac('sha256', keys.subarray(32)).update(authenticated).digest()]));
  return { privateKey, publicKey, body, plaintext };
}

test('provisioning key is unexportable and has a Signal Curve25519 public encoding', async () => {
  const pair = await generateProvisioningKeypair();
  assert.equal(pair.publicKey.length, 33); assert.equal(pair.publicKey[0], 5);
  assert.equal(pair.privateKey.extractable, false);
  await assert.rejects(crypto.subtle.exportKey('pkcs8', pair.privateKey));
});
test('identity public derivation matches the RFC 7748 Alice X25519 vector', async () => {
  const key = Buffer.from('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a', 'hex');
  assert.equal(Buffer.from(await identityPublicKey(key)).toString('hex'),
    '058520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a');
});
test('provisioning decrypts independently constructed Node/OpenSSL envelope', async () => {
  const fixture = await envelopeFixture();
  assert.deepEqual(Buffer.from(await decryptProvisioningEnvelope(fixture.privateKey, fixture)), fixture.plaintext);
});
test('provisioning authenticates IV, ciphertext and MAC before decryption', async () => {
  const fixture = await envelopeFixture();
  for (const offset of [1, 17, fixture.body.length - 1]) {
    const body = fixture.body.slice(); body[offset] ^= 1;
    await assert.rejects(decryptProvisioningEnvelope(fixture.privateKey, { ...fixture, body }), /authentication failed/);
  }
  const wrong = await generateProvisioningKeypair();
  await assert.rejects(decryptProvisioningEnvelope(wrong.privateKey, fixture), /authentication failed/);
});
test('malformed and oversized provisioning envelopes fail closed', async () => {
  const fixture = await envelopeFixture();
  for (const body of [new Uint8Array(0), new Uint8Array(64), new Uint8Array(1024 * 1024 + 1), fixture.body.slice(1)])
    await assert.rejects(decryptProvisioningEnvelope(fixture.privateKey, { ...fixture, body }), /Malformed|unsupported/);
  const publicKey = fixture.publicKey.slice(); publicKey[0] = 6;
  await assert.rejects(decryptProvisioningEnvelope(fixture.privateKey, { ...fixture, publicKey }), /public key type/);
  const zero = new Uint8Array(33); zero[0] = 5;
  await assert.rejects(decryptProvisioningEnvelope(fixture.privateKey, { ...fixture, publicKey: zero }));
});
test('encrypted device name decrypts using independent Node/OpenSSL operations', async () => {
  const identity = generateKeyPairSync('x25519');
  const publicKey = signal(identity.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32));
  const name = 'Twang · 蜘蛛';
  const encrypted = await encryptDeviceName(name, publicKey);
  const spkiPrefix = Buffer.from('302a300506032b656e032100', 'hex');
  const { createPublicKey } = await import('node:crypto');
  const ephemeral = createPublicKey({ format: 'der', type: 'spki', key: Buffer.concat([spkiPrefix, encrypted.ephemeralPublic.subarray(1)]) });
  const secret = diffieHellman({ privateKey: identity.privateKey, publicKey: ephemeral });
  const key1 = createHmac('sha256', secret).update('auth').digest();
  const key2 = createHmac('sha256', secret).update('cipher').digest();
  const cipherKey = createHmac('sha256', key2).update(encrypted.syntheticIv).digest();
  const decipher = createDecipheriv('aes-256-ctr', cipherKey, Buffer.alloc(16));
  const plaintext = Buffer.concat([decipher.update(encrypted.ciphertext), decipher.final()]);
  assert.equal(plaintext.toString('utf8'), name);
  assert.deepEqual(createHmac('sha256', key1).update(plaintext).digest().subarray(0,16), Buffer.from(encrypted.syntheticIv));
  await assert.rejects(encryptDeviceName('', publicKey), /Device name/);
  await assert.rejects(encryptDeviceName('a'.repeat(257), publicKey), /Device name/);
});

test('actual libsignal WASM creates signed Curve25519 and round-3 Kyber prekeys with durable records', async () => {
  const lib = await import('@getmaapp/signal-wasm');
  await lib.default({ module_or_path: await readFile(new URL('../node_modules/@getmaapp/signal-wasm/signal_wasm_bg.wasm', import.meta.url)) });
  // Public fixture signed independently with the official native
  // @signalapp/libsignal-client 0.101.0, using RFC 7748's published Alice scalar.
  // It is not generated by the WASM implementation under test.
  const knownPublic = lib.WasmPublicKey.deserialize(Buffer.from('058520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a', 'hex'));
  const knownMessage = Buffer.from('Twang official libsignal XEdDSA interoperability fixture');
  const knownSignature = Buffer.from('f1fafa47465dede1c629630bf9408120f2debf3df1e1a43d62bfdc7c139f796f4ca491310d93bafbdcff9b8ead900a8aaa8016ad2c437c0dacd6f04b0c31418c', 'hex');
  assert.equal(lib.verifyIdentitySignature(knownPublic, knownMessage, knownSignature), true);
  knownMessage[0] ^= 1;
  assert.equal(lib.verifyIdentitySignature(knownPublic, knownMessage, knownSignature), false);
  knownPublic.free();
  const identity = lib.WasmPrivateKey.generate();
  const scalar = identity.serialize();
  const publicKey = identity.getPublicKey();
  const keys = await generateRegistrationKeys(scalar, { module: lib, keyId: 17 });
  assert.ok(keys.registrationId > 0 && keys.registrationId < 16384);
  assert.deepEqual(keys.identityPublic, publicKey.serialize());
  assert.equal(keys.signedPreKey.keyId, 17); assert.equal(keys.pqLastResortPreKey.keyId, 17);
  assert.equal(keys.signedPreKey.publicKey[0], 5); assert.equal(keys.pqLastResortPreKey.publicKey[0], 8);
  assert.equal(keys.pqLastResortPreKey.publicKey.length, 1569);
  assert.equal(lib.verifyIdentitySignature(publicKey, keys.signedPreKey.publicKey, keys.signedPreKey.signature), true);
  assert.equal(lib.verifyIdentitySignature(publicKey, keys.pqLastResortPreKey.publicKey, keys.pqLastResortPreKey.signature), true);
  const corrupted = keys.pqLastResortPreKey.publicKey.slice(); corrupted[15] ^= 1;
  assert.equal(lib.verifyIdentitySignature(publicKey, corrupted, keys.pqLastResortPreKey.signature), false);
  const signedStore = new lib.WasmInMemSignedPreKeyStore();
  const kyberStore = new lib.WasmInMemKyberPreKeyStore();
  await signedStore.import_signed_pre_key(17, keys.signedPreKeyRecord);
  await kyberStore.import_kyber_pre_key(17, keys.pqLastResortPreKeyRecord);
  assert.deepEqual(await signedStore.export_signed_pre_key(17), keys.signedPreKeyRecord);
  assert.deepEqual(await kyberStore.export_kyber_pre_key(17), keys.pqLastResortPreKeyRecord);
  signedStore.free(); kyberStore.free(); publicKey.free(); identity.free(); scalar.fill(0);
});
