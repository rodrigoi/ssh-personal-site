/**
 * Cryptographic utilities for SSH server
 * This module handles encryption, decryption, MAC, and key derivation
 */

import {
  createCipheriv,
  createDecipheriv,
  createDiffieHellmanGroup,
  createHash,
  createHmac,
  generateKeyPairSync,
  randomBytes,
} from "node:crypto";

/**
 * Generates an Ed25519 host key pair
 * Ed25519 is a modern elliptic curve signature scheme
 */
export function generateHostKey() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return { publicKey, privateKey };
}

/**
 * Performs Diffie-Hellman key exchange using group14 (2048-bit MODP)
 * This is used to establish a shared secret with the client
 */
export class DHGroup14Exchange {
  private dh: ReturnType<typeof createDiffieHellmanGroup>;
  private sharedSecret: Buffer | null = null;

  constructor() {
    // modp14 is a standardized 2048-bit MODP group (RFC 3526)
    this.dh = createDiffieHellmanGroup("modp14");
    this.dh.generateKeys();
  }

  /**
   * Get our public key to send to the client
   */
  getPublicKey(): Buffer {
    return this.dh.getPublicKey();
  }

  /**
   * Compute the shared secret from the client's public key
   */
  computeSecret(clientPublicKey: Buffer): Buffer {
    this.sharedSecret = this.dh.computeSecret(clientPublicKey);
    return this.sharedSecret;
  }

  getSharedSecret(): Buffer {
    if (!this.sharedSecret) {
      throw new Error("Shared secret not yet computed");
    }
    return this.sharedSecret;
  }
}

/**
 * Derives encryption/MAC keys from the shared secret
 * SSH uses a key derivation function based on hashing
 *
 * Key = HASH(K || H || X || session_id)
 * Where:
 * - K is the shared secret
 * - H is the exchange hash
 * - X is a single character ('A', 'B', 'C', 'D', 'E', or 'F')
 * - session_id is the exchange hash from the first key exchange
 */
export function deriveKey(
  sharedSecret: Buffer,
  exchangeHash: Buffer,
  char: string,
  sessionId: Buffer,
  keyLength: number
): Buffer {
  const hash = createHash("sha256");

  // SSH requires the shared secret to be encoded as mpint (SSH integer format)
  const mpint = encodeMPInt(sharedSecret);

  hash.update(mpint);
  hash.update(exchangeHash);
  hash.update(Buffer.from(char, "ascii"));
  hash.update(sessionId);

  let key = hash.digest();

  // If we need more key material, keep hashing
  while (key.length < keyLength) {
    const hash2 = createHash("sha256");
    hash2.update(mpint);
    hash2.update(exchangeHash);
    hash2.update(key);
    key = Buffer.concat([key, hash2.digest()]);
  }

  return key.slice(0, keyLength);
}

/**
 * Encodes a buffer as SSH mpint (multiple precision integer)
 * If the high bit is set, we need to prepend a zero byte
 */
function encodeMPInt(buf: Buffer): Buffer {
  const needsZero = buf[0] & 0x80;
  const length = buf.length + (needsZero ? 1 : 0);
  const result = Buffer.allocUnsafe(4 + length);

  // Write length
  result.writeUInt32BE(length, 0);

  if (needsZero) {
    result[4] = 0;
    buf.copy(result, 5);
  } else {
    buf.copy(result, 4);
  }

  return result;
}

/**
 * Simple cipher for AES-128-CTR encryption
 */
export class AES128CTR {
  private cipher: ReturnType<typeof createCipheriv>;
  private decipher: ReturnType<typeof createDecipheriv>;

  constructor(encryptKey: Buffer, encryptIV: Buffer, decryptKey: Buffer, decryptIV: Buffer) {
    this.cipher = createCipheriv("aes-128-ctr", encryptKey, encryptIV);
    this.decipher = createDecipheriv("aes-128-ctr", decryptKey, decryptIV);
  }

  encrypt(data: Buffer): Buffer {
    return this.cipher.update(data);
  }

  decrypt(data: Buffer): Buffer {
    return this.decipher.update(data);
  }
}

/**
 * HMAC-SHA256 for message authentication
 */
export class HMACSHA256 {
  private encryptKey: Buffer;
  private decryptKey: Buffer;

  constructor(encryptKey: Buffer, decryptKey: Buffer) {
    this.encryptKey = encryptKey;
    this.decryptKey = decryptKey;
  }

  /**
   * Compute MAC for outgoing packet
   * MAC = HMAC(key, sequence_number || unencrypted_packet)
   */
  computeMAC(sequenceNumber: number, packet: Buffer): Buffer {
    const seqBuf = Buffer.allocUnsafe(4);
    seqBuf.writeUInt32BE(sequenceNumber, 0);

    const hmac = createHmac("sha256", this.encryptKey);
    hmac.update(seqBuf);
    hmac.update(packet);
    return hmac.digest();
  }

  /**
   * Verify MAC for incoming packet
   */
  verifyMAC(sequenceNumber: number, packet: Buffer, receivedMAC: Buffer): boolean {
    const seqBuf = Buffer.allocUnsafe(4);
    seqBuf.writeUInt32BE(sequenceNumber, 0);

    const hmac = createHmac("sha256", this.decryptKey);
    hmac.update(seqBuf);
    hmac.update(packet);
    const expectedMAC = hmac.digest();

    return expectedMAC.equals(receivedMAC);
  }
}

/**
 * Sign data with Ed25519 private key
 */
export function signData(privateKey: any, data: Buffer): Buffer {
  const signature = require("node:crypto").sign(null, data, privateKey);
  return signature;
}
