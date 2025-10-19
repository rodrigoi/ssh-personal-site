/**
 * Pure TypeScript SSH Server
 * Educational implementation of SSH protocol
 *
 * This demonstrates:
 * - SSH version exchange
 * - Diffie-Hellman key exchange (group14-sha256)
 * - AES-128-CTR encryption
 * - HMAC-SHA256 message authentication
 * - Ed25519 host key signatures
 * - User authentication (simplified)
 * - SSH channels for communication
 *
 * When a client connects via SSH, it will receive "Hello World" and disconnect.
 *
 * Usage:
 *   bun src/index.ts
 *
 * Then connect with:
 *   ssh -p 2222 localhost
 */

import { createSSHServer } from "./ssh-server";
import { loadOrGenerateHostKey } from "./host-key";

// Load or generate persistent host key
console.log("Initializing SSH server...");
const hostKeyPair = loadOrGenerateHostKey();

// Start the SSH server on port 2222
createSSHServer(2222, hostKeyPair);
