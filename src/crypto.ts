
import { createDiffieHellman, createSign, createHash, createPublicKey, sign, createPrivateKey } from "node:crypto";

// For simplicity, we'll use a hardcoded host key.
// In a real application, this should be loaded from a file.
const privateHostKey = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIKRLGC71XzofCecqQAnbuxWSvwYaCNxQMN2gpp0YI/y4
-----END PRIVATE KEY-----`;

const publicHostKey = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAnUyZS59O5PgrIoCcEvo8DBTeKyp9S1607PvtCIl/ZUg=
-----END PUBLIC KEY-----`;

// Extract raw Ed25519 public key (32 bytes)
const getHostPublicKeyBytes = (): Uint8Array => {
  const pubKey = createPublicKey(publicHostKey);
  const exported = pubKey.export({ type: 'spki', format: 'der' });
  // Ed25519 public key is the last 32 bytes of the SPKI format
  return new Uint8Array(exported.slice(-32));
};

export const hostPublicKeyBytes = getHostPublicKeyBytes();

// Group 14 prime (2048-bit MODP Group from RFC 3526)
const group14Prime = Buffer.from(
  'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1' +
  '29024E088A67CC74020BBEA63B139B22514A08798E3404DD' +
  'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245' +
  'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' +
  'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D' +
  'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F' +
  '83655D23DCA3AD961C62F356208552BB9ED529077096966D' +
  '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' +
  'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9' +
  'DE2BCBF6955817183995497CEA956AE515D2261898FA0510' +
  '15728E5A8AACAA68FFFFFFFFFFFFFFFF',
  'hex'
);

export const generateKeys = () => {
  // Use the predefined diffie-hellman-group14-sha256 group (RFC 3526)
  // Group 14 uses a 2048-bit MODP group with generator 2
  const dh = createDiffieHellman(group14Prime, Buffer.from([2]));
  const publicKey = dh.generateKeys();
  return { dh, publicKey };
};

export const computeSharedSecret = (dh: any, clientPublicKey: Uint8Array) => {
  return dh.computeSecret(Buffer.from(clientPublicKey));
};

export const signData = (data: Uint8Array) => {
  // Ed25519 signing using the crypto.sign() method
  // This method automatically handles Ed25519 keys without needing to specify a hash algorithm
  return sign(null, Buffer.from(data), createPrivateKey(privateHostKey));
};

export const hashData = (data: Uint8Array) => {
  const hash = createHash("sha256");
  hash.update(Buffer.from(data));
  return hash.digest();
};

/**
 * Derive encryption keys according to RFC 4253 Section 7.2
 * Key derivation: HASH(K || H || X || session_id)
 * If more bytes needed: HASH(K || H || K1), HASH(K || H || K1 || K2), etc.
 *
 * Note: K is the shared secret as mpint (big-endian bytes with length prefix)
 */
export const deriveKey = (
  K: Buffer,
  H: Buffer,
  letter: string,
  sessionId: Buffer,
  neededBytes: number
): Buffer => {
  const hash = createHash("sha256");

  // K1 = HASH(K || H || X || session_id)
  hash.update(K);
  hash.update(H);
  hash.update(Buffer.from(letter, "utf8"));
  hash.update(sessionId);

  let keyMaterial = hash.digest();

  // If we need more bytes, keep hashing
  while (keyMaterial.length < neededBytes) {
    const hash2 = createHash("sha256");
    hash2.update(K);
    hash2.update(H);
    hash2.update(keyMaterial);
    keyMaterial = Buffer.concat([keyMaterial, hash2.digest()]);
  }

  return keyMaterial.slice(0, neededBytes);
};
