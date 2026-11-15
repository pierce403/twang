// Signal provisioning algorithms, matching Signal-Desktop ProvisioningCipher and
// Crypto.encryptDeviceName. Private keys and decrypted provisioning data remain
// in this browser. No registration or network operation belongs in this module.
const utf8 = new TextEncoder();
const MAX_PROVISION_BODY = 1024 * 1024;
const PKCS8_X25519 = new Uint8Array([0x30,0x2e,0x02,0x01,0,0x30,0x05,0x06,0x03,0x2b,0x65,0x6e,0x04,0x22,0x04,0x20]);
const concat = (...values) => {
  const result = new Uint8Array(values.reduce((length, value) => length + value.length, 0));
  let offset = 0;
  for (const value of values) { result.set(value, offset); offset += value.length; }
  return result;
};
function bytes(value, length, label) {
  if (!(value instanceof Uint8Array) || (length !== undefined && value.length !== length))
    throw new Error(`Invalid ${label}`);
  return value;
}
function rawPublic(value) {
  bytes(value, 33, 'Signal public key');
  if (value[0] !== 5) throw new Error('Unsupported Signal public key type');
  return value.subarray(1);
}
async function importPrivate(value) {
  bytes(value, 32, 'Signal private key');
  const encoded = concat(PKCS8_X25519, value);
  try { return await crypto.subtle.importKey('pkcs8', encoded, { name: 'X25519' }, false, ['deriveBits']); }
  finally { encoded.fill(0); }
}
async function agree(privateKey, serializedPublic) {
  const publicKey = await crypto.subtle.importKey('raw', rawPublic(serializedPublic), { name: 'X25519' }, false, []);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'X25519', public: publicKey }, privateKey, 256));
}
async function hmac(keyBytes, input) {
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, input));
}
export async function generateProvisioningKeypair() {
  let pair;
  try { pair = await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']); }
  catch { throw new Error('This browser does not support the X25519 cryptography required for Signal linking'); }
  const publicKey = concat(new Uint8Array([5]), new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey)));
  return { publicKey, privateKey: pair.privateKey };
}

// Derive a Signal-format public key from a provisioned scalar using X25519's
// standard base point. This avoids depending on private JWK export behavior.
export async function identityPublicKey(privateKeyBytes) {
  const base = new Uint8Array(33); base[0] = 5; base[1] = 9;
  return concat(new Uint8Array([5]), await agree(await importPrivate(privateKeyBytes), base));
}

export async function decryptProvisioningEnvelope(privateKey, envelope) {
  const original = bytes(envelope?.body, undefined, 'provisioning envelope body');
  if (original.length < 65 || original.length > MAX_PROVISION_BODY || original[0] !== 1 || (original.length - 49) % 16)
    throw new Error('Malformed or unsupported Signal provisioning envelope');
  // Snapshot caller-owned buffers before awaiting. The bytes decrypted below
  // must be the same bytes authenticated above, even if the caller reuses a view.
  const body = original.slice();
  const publicKey = bytes(envelope?.publicKey, 33, 'Signal public key').slice();
  // Import and DH reject invalid encodings and low-order/all-zero shared secrets.
  const secret = await agree(privateKey, publicKey);
  let derived;
  try {
    const input = await crypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveBits']);
    derived = new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256',
      salt: new Uint8Array(32), info: utf8.encode('TextSecure Provisioning Message') }, input, 512));
    const authenticated = body.subarray(0, body.length - 32);
    const mac = body.subarray(body.length - 32);
    const macKey = await crypto.subtle.importKey('raw', derived.subarray(32),
      { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    if (!await crypto.subtle.verify('HMAC', macKey, mac, authenticated))
      throw new Error('Signal provisioning envelope authentication failed');
    const aesKey = await crypto.subtle.importKey('raw', derived.subarray(0, 32), 'AES-CBC', false, ['decrypt']);
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-CBC', iv: body.subarray(1, 17) },
      aesKey, body.subarray(17, body.length - 32));
    return new Uint8Array(plaintext);
  } finally { secret.fill(0); derived?.fill(0); }
}

export async function encryptDeviceName(name, identityPublic) {
  const plaintext = utf8.encode(name);
  if (!plaintext.length || plaintext.length > 256) throw new Error('Device name must contain 1–256 UTF-8 bytes');
  const ephemeral = await generateProvisioningKeypair();
  const secret = await agree(ephemeral.privateKey, identityPublic);
  let authKey, cipherSeed, cipherKey;
  try {
    authKey = await hmac(secret, utf8.encode('auth'));
    const syntheticIv = (await hmac(authKey, plaintext)).slice(0, 16);
    cipherSeed = await hmac(secret, utf8.encode('cipher'));
    cipherKey = await hmac(cipherSeed, syntheticIv);
    const key = await crypto.subtle.importKey('raw', cipherKey, 'AES-CTR', false, ['encrypt']);
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CTR', counter: new Uint8Array(16), length: 128 }, key, plaintext));
    return { ephemeralPublic: ephemeral.publicKey, syntheticIv, ciphertext };
  } finally { secret.fill(0); authKey?.fill(0); cipherSeed?.fill(0); cipherKey?.fill(0); plaintext.fill(0); }
}

let signalModule;
export function loadSignalCrypto() {
  if (!signalModule) signalModule = import(new URL('../vendor/signal/signal_wasm.js', import.meta.url).href)
    .then(async module => {
      await module.default({ module_or_path: new URL('../vendor/signal/signal_wasm_bg.wasm', import.meta.url) });
      return module;
    }).catch(error => { signalModule = undefined; throw error; });
  return signalModule;
}

// Uses the pinned libsignal WASM wrapper, not substitute Ed25519 or ML-KEM keys.
// Records contain private material and MUST be saved locally before server link.
export async function generateRegistrationKeys(identityPrivate, { keyId = 1, module } = {}) {
  bytes(identityPrivate, 32, 'identity private key');
  if (!Number.isInteger(keyId) || keyId < 1 || keyId > 0xffffff) throw new Error('Invalid prekey identifier');
  const lib = module ?? await loadSignalCrypto();
  const privateKey = lib.WasmPrivateKey.deserialize(identityPrivate);
  const publicKey = privateKey.getPublicKey();
  const identity = new lib.WasmIdentityKeyPair(publicKey, privateKey);
  const signedStore = new lib.WasmInMemSignedPreKeyStore();
  const kyberStore = new lib.WasmInMemKyberPreKeyStore();
  let signed, kyber;
  try {
    signed = await lib.generateSignedPreKey(keyId, identity, signedStore);
    kyber = await lib.generateKyberPreKey(keyId, identity, kyberStore);
    const identityPublic = identity.public_key;
    try {
      const signedPublic = signed.public_key;
      const kyberPublic = kyber.public_key;
      const signedSignature = signed.signature;
      const kyberSignature = kyber.signature;
      if (signedPublic.length !== 33 || signedPublic[0] !== 5 ||
          kyberPublic.length !== 1569 || kyberPublic[0] !== 8 ||
          !lib.verifyIdentitySignature(identityPublic, signedPublic, signedSignature) ||
          !lib.verifyIdentitySignature(identityPublic, kyberPublic, kyberSignature))
        throw new Error('Generated Signal prekeys failed format or signature verification');
      return { registrationId: lib.generateRegistrationId(), identityPublic: identityPublic.serialize(),
        signedPreKey: { keyId: signed.id, publicKey: signedPublic, signature: signedSignature },
        pqLastResortPreKey: { keyId: kyber.id, publicKey: kyberPublic, signature: kyberSignature },
        signedPreKeyRecord: signed.record, pqLastResortPreKeyRecord: kyber.record };
    } finally { identityPublic.free(); }
  } finally {
    signed?.free(); kyber?.free(); signedStore.free(); kyberStore.free(); identity.free();
    publicKey.free(); privateKey.free();
  }
}
