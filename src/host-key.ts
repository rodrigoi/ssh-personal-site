/**
 * Host key management - persistent Ed25519 key storage
 */

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { generateKeyPairSync, KeyObject } from "node:crypto";

const HOST_KEY_PATH = ".ssh_host_ed25519_key";
const HOST_PUB_KEY_PATH = ".ssh_host_ed25519_key.pub";

export interface HostKeyPair {
  publicKey: KeyObject;
  privateKey: KeyObject;
}

/**
 * Load or generate a persistent host key
 *
 * If the key files exist, load them from disk.
 * Otherwise, generate a new keypair and save it.
 */
export function loadOrGenerateHostKey(): HostKeyPair {
  if (existsSync(HOST_KEY_PATH) && existsSync(HOST_PUB_KEY_PATH)) {
    console.log("Loading existing host key from disk...");
    return loadHostKey();
  } else {
    console.log("Generating new host key...");
    return generateAndSaveHostKey();
  }
}

/**
 * Generate a new Ed25519 keypair and save to disk
 */
function generateAndSaveHostKey(): HostKeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");

  // Export keys in PEM format
  const publicKeyPEM = publicKey.export({ type: "spki", format: "pem" });
  const privateKeyPEM = privateKey.export({ type: "pkcs8", format: "pem" });

  // Save to disk
  writeFileSync(HOST_KEY_PATH, privateKeyPEM as string, { mode: 0o600 });
  writeFileSync(HOST_PUB_KEY_PATH, publicKeyPEM as string, { mode: 0o644 });

  console.log(`Host key saved to ${HOST_KEY_PATH}`);
  console.log(`Public key saved to ${HOST_PUB_KEY_PATH}`);

  // Get fingerprint for display
  const pubKeyRaw = publicKey.export({ type: "spki", format: "der" });
  const fingerprint = require("node:crypto")
    .createHash("sha256")
    .update(pubKeyRaw)
    .digest("base64")
    .replace(/=+$/, "");

  console.log(`Fingerprint: SHA256:${fingerprint}`);

  return { publicKey, privateKey };
}

/**
 * Load host key from disk
 */
function loadHostKey(): HostKeyPair {
  const privateKeyPEM = readFileSync(HOST_KEY_PATH, "utf8");
  const publicKeyPEM = readFileSync(HOST_PUB_KEY_PATH, "utf8");

  const privateKey = require("node:crypto").createPrivateKey(privateKeyPEM);
  const publicKey = require("node:crypto").createPublicKey(publicKeyPEM);

  // Get fingerprint for display
  const pubKeyRaw = publicKey.export({ type: "spki", format: "der" });
  const fingerprint = require("node:crypto")
    .createHash("sha256")
    .update(pubKeyRaw)
    .digest("base64")
    .replace(/=+$/, "");

  console.log(`Fingerprint: SHA256:${fingerprint}`);

  return { publicKey, privateKey };
}
