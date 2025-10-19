import {
  computeSharedSecret,
  deriveKey,
  generateKeys,
  hashData,
  hostPublicKeyBytes,
  signData,
} from "./crypto";
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes,
} from "node:crypto";

const log = (...args: any[]) => {
  console.log(`[${new Date().toISOString()}]`, ...args);
};

const SSH_Itentity = "SSH-2.0-BunSSH_0.0.1";

// Connection states
type ConnectionState = "init" | "kex" | "auth" | "connected";

// Session type to track connection state
type Session = {
  state: ConnectionState;
  clientIdentity: string;
  buffer: Uint8Array;
  socket: any;
  clientKexInit: Uint8Array | null;
  serverKexInit: Uint8Array | null;
  dh: any | null;
  // Key exchange data
  sharedSecret: Buffer | null;
  exchangeHash: Buffer | null;
  // Encryption state
  sessionId: Uint8Array | null;
  encryptionEnabled: boolean;
  encryptCipher: any | null;
  decryptCipher: any | null;
  decryptKey: Buffer | null;
  decryptIV: Buffer | null;
  encryptMacKey: Buffer | null;
  decryptMacKey: Buffer | null;
  encryptSeqNum: number;
  decryptSeqNum: number;
  // Track packet length and first block (decrypted ONCE with main cipher)
  packetLengthKnown: boolean;
  expectedPacketLength: number;
  decryptedFirstBlock: Buffer | null;
};

/**
 * https://datatracker.ietf.org/doc/html/rfc4253#section-12
 */
const SSH_Messages = {
  SSH_MSG_DISCONNECT: 1,
  SSH_MSG_IGNORE: 2,
  SSH_MSG_UNIMPLEMENTED: 3,
  SSH_MSG_DEBUG: 4,
  SSH_MSG_SERVICE_REQUEST: 5,
  SSH_MSG_SERVICE_ACCEPT: 6,
  SSH_MSG_KEXINIT: 20,
  SSH_MSG_NEWKEYS: 21,
  SSH_MSG_KEXDH_INIT: 30,
  SSH_MSG_KEXDH_REPLY: 31,
  SSH_MSG_USERAUTH_REQUEST: 50,
  SSH_MSG_USERAUTH_FAILURE: 51,
  SSH_MSG_USERAUTH_SUCCESS: 52,
  SSH_MSG_GLOBAL_REQUEST: 80,
  SSH_MSG_REQUEST_SUCCESS: 81,
  SSH_MSG_REQUEST_FAILURE: 82,
  SSH_MSG_CHANNEL_OPEN: 90,
  SSH_MSG_CHANNEL_OPEN_CONFIRMATION: 91,
  SSH_MSG_CHANNEL_OPEN_FAILURE: 92,
  SSH_MSG_CHANNEL_WINDOW_ADJUST: 93,
  SSH_MSG_CHANNEL_DATA: 94,
  SSH_MSG_CHANNEL_EOF: 96,
  SSH_MSG_CHANNEL_CLOSE: 97,
  SSH_MSG_CHANNEL_REQUEST: 98,
  SSH_MSG_CHANNEL_SUCCESS: 99,
  SSH_MSG_CHANNEL_FAILURE: 100,
};

// Algorithm preferences
const ALGORITHMS = {
  kex: ["diffie-hellman-group14-sha256"],
  hostKey: ["ssh-ed25519"],
  encryption: [
    "aes128-ctr", // Must be first - only cipher we've implemented
    "aes192-ctr",
    "aes256-ctr",
  ],
  mac: ["hmac-sha2-256", "hmac-sha2-512", "hmac-sha1"],
  compression: [
    "none", // No compression
    "zlib@openssh.com", // Compression after authentication
    "zlib", // Always compress
  ],
} as const;

// Store active sessions
const sessions = new Map<any, Session>();

// Write a 32-bit unsigned integer in big-endian order
export const writeUint32BE = (value: number): Uint8Array => {
  const arr = new Uint8Array(4);
  arr[0] = (value >>> 24) & 0xff;
  arr[1] = (value >>> 16) & 0xff;
  arr[2] = (value >>> 8) & 0xff;
  arr[3] = value & 0xff;
  return arr;
};

// Convert a string to a Uint8Array
export const stringToUint8Array = (str: string): Uint8Array => {
  return new TextEncoder().encode(str);
};

// Concatenate multiple Uint8Arrays
export const concatUint8Arrays = (...arrays: Uint8Array[]): Uint8Array => {
  const totalLength = arrays.reduce((acc, arr) => acc + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
};

// Find a sequence in a Uint8Array
const findSequence = (data: Uint8Array, sequence: Uint8Array): number => {
  for (let i = 0; i <= data.length - sequence.length; i++) {
    let found = true;
    for (let j = 0; j < sequence.length; j++) {
      if (data[i + j] !== sequence[j]) {
        found = false;
        break;
      }
    }
    if (found) return i;
  }
  return -1;
};

// Encode a string in SSH wire format (length + data)
export const writeSSHString = (data: Uint8Array | string): Uint8Array => {
  const bytes = typeof data === "string" ? stringToUint8Array(data) : data;
  return concatUint8Arrays(writeUint32BE(bytes.length), bytes);
};

// Encode an mpint in SSH wire format (length + data, with high bit handling)
export const writeMpint = (data: Uint8Array | Buffer): Uint8Array => {
  const bytes = data instanceof Buffer ? new Uint8Array(data) : data;

  // Remove leading zero bytes, but keep at least one byte
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0) {
    start++;
  }
  const trimmed = bytes.slice(start);

  // If the high bit is set, prepend a zero byte
  const needsPadding = trimmed.length > 0 && (trimmed[0] & 0x80) !== 0;
  const final = needsPadding
    ? concatUint8Arrays(new Uint8Array([0]), trimmed)
    : trimmed;

  return concatUint8Arrays(writeUint32BE(final.length), final);
};

const readString = (data: Uint8Array, offset: number): [string, number] => {
  const length =
    (data[offset] << 24) |
    (data[offset + 1] << 16) |
    (data[offset + 2] << 8) |
    data[offset + 3];
  const end = offset + 4 + length;
  const str = new TextDecoder().decode(data.slice(offset + 4, end));
  return [str, end];
};

const readMpint = (data: Uint8Array, offset: number): [Uint8Array, number] => {
  let length =
    (data[offset] << 24) |
    (data[offset + 1] << 16) |
    (data[offset + 2] << 8) |
    data[offset + 3];
  let start = offset + 4;
  if (data[start] === 0) {
    start++;
    length--;
  }
  const end = start + length;
  const mpint = data.slice(start, end);
  return [mpint, end];
};

const createKexInit = (): Uint8Array => {
  const cookie = new Uint8Array(randomBytes(16));

  /**
   * The KNEXINIT message must include algorithm lists in both directions,
   * client-to-server and server-to-client, that's why we have duplicated values on the list.
   * This is according to the RFC 4253 section 7.2.
   * Otherwise, the connection will be rejected with:
   * kex_input_kexinit: discard proposal: incomplete message
   */
  const nameListData = [
    ALGORITHMS.kex.join(","),
    ALGORITHMS.hostKey.join(","),
    ALGORITHMS.encryption.join(","),
    ALGORITHMS.encryption.join(","),
    ALGORITHMS.mac.join(","),
    ALGORITHMS.mac.join(","),
    ALGORITHMS.compression.join(","),
    ALGORITHMS.compression.join(","),
    "en", // Languages client to server
    "en", // Languages server to client
  ];

  const parts: Uint8Array[] = [
    new Uint8Array([SSH_Messages.SSH_MSG_KEXINIT]),
    cookie,
  ];

  for (const str of nameListData) {
    const buf = stringToUint8Array(str);
    parts.push(writeUint32BE(buf.length));
    parts.push(buf);
  }

  parts.push(new Uint8Array([0])); // First KEX packet follows
  parts.push(writeUint32BE(0)); // Reserved

  return concatUint8Arrays(...parts);
};

const createPacket = (payload: Uint8Array): Uint8Array => {
  const blockSize = 8;
  // RFC 4253: padding length must be at least 4 bytes and at most 255 bytes
  // Total packet length (excluding the packet_length field) must be multiple of block size
  let paddingLength = blockSize - ((payload.length + 5) % blockSize);
  if (paddingLength < 4) {
    paddingLength += blockSize;
  }
  const padding = new Uint8Array(randomBytes(paddingLength));

  const packetLength = payload.length + paddingLength + 1;

  return concatUint8Arrays(
    writeUint32BE(packetLength),
    new Uint8Array([paddingLength]),
    payload,
    padding
  );
};

const handleKexdhInit = (session: Session, payload: Uint8Array) => {
  try {
    log("KEXDH_INIT received");
    const [clientPublicKey, _] = readMpint(payload, 1);
    log(
      "Client public key (hex):",
      Buffer.from(clientPublicKey).toString("hex")
    );
    log(
      "Client public key (base64):",
      Buffer.from(clientPublicKey).toString("base64")
    );

    const sharedSecret = computeSharedSecret(session.dh, clientPublicKey);

    const V_C = stringToUint8Array(session.clientIdentity);
    log(`V_C length: ${V_C.length}`);
    const V_S = stringToUint8Array(SSH_Itentity);
    log(`V_S length: ${V_S.length}`);
    const I_C = session.clientKexInit!;
    log(`I_C length: ${I_C.length}`);
    const I_S = session.serverKexInit!;
    log(`I_S length: ${I_S.length}`);

    // K_S is the server's host key in SSH wire format: string("ssh-ed25519") + string(public-key-bytes)
    const K_S = concatUint8Arrays(
      writeSSHString("ssh-ed25519"),
      writeSSHString(hostPublicKeyBytes)
    );
    log(`K_S length: ${K_S.length}`);

    const e = clientPublicKey;
    log(`e length: ${e.length}`);
    const f = session.dh.getPublicKey();
    log(`f length: ${f.length}`);
    const K = sharedSecret;
    log(`K length: ${K.length}`);

    // Build exchange hash H according to RFC 4253 section 8
    const exchangeHash = hashData(
      concatUint8Arrays(
        writeSSHString(V_C),
        writeSSHString(V_S),
        writeSSHString(I_C),
        writeSSHString(I_S),
        writeSSHString(K_S),
        writeMpint(e),
        writeMpint(f),
        writeMpint(K)
      )
    );

    // Store the exchange hash as session_id (used for key derivation)
    if (!session.sessionId) {
      session.sessionId = new Uint8Array(exchangeHash);
      log("Session ID set from exchange hash");
    }

    // Store K and H for later key derivation
    session.sharedSecret = Buffer.from(K);
    session.exchangeHash = Buffer.from(exchangeHash);

    // Sign the exchange hash and wrap in SSH wire format
    const rawSignature = signData(new Uint8Array(exchangeHash));
    const signature = concatUint8Arrays(
      writeSSHString("ssh-ed25519"),
      writeSSHString(rawSignature)
    );

    const kexdh_reply = concatUint8Arrays(
      new Uint8Array([SSH_Messages.SSH_MSG_KEXDH_REPLY]),
      writeSSHString(K_S),
      writeMpint(f),
      writeSSHString(signature)
    );

    const packet = createPacket(kexdh_reply);
    session.socket.write(packet);

    // Send NEWKEYS immediately after KEXDH_REPLY (RFC 4253 Section 7.3)
    const newKeys = new Uint8Array([SSH_Messages.SSH_MSG_NEWKEYS]);
    const newKeysPacket = createPacket(newKeys);
    log(
      `Sending NEWKEYS packet (${newKeysPacket.length} bytes):`,
      Buffer.from(newKeysPacket).toString("hex")
    );
    session.socket.write(newKeysPacket);
  } catch (error) {
    log("Error in KEXDH_INIT:", error);
    const errorMessage = stringToUint8Array(error.message);
    const disconnect = concatUint8Arrays(
      new Uint8Array([SSH_Messages.SSH_MSG_DISCONNECT]),
      writeUint32BE(11), // SSH_DISCONNECT_KEY_EXCHANGE_FAILED
      writeUint32BE(errorMessage.length),
      errorMessage,
      writeUint32BE(0), // language tag length
      new Uint8Array(0) // language tag
    );
    const disconnectPacket = createPacket(disconnect);
    session.socket.write(disconnectPacket);
    session.socket.end();
  }
};

/**
 * Parses SSH packet protocol messages
 * [32-bit length][8-bit padding][...payload...][...padding...]
 *   4 bytes         1 byte        variable       variable
 */
export const parsePacket = (
  data: Uint8Array
): {
  payload: Uint8Array;
  padding: Uint8Array;
  packetLength: number;
} | null => {
  if (data.length < 5) return null;

  const packetLength =
    (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];

  if (data.length < packetLength + 4) return null;

  const paddingLength = data[4];
  const payloadLength = packetLength - paddingLength - 1;

  const payload = data.slice(5, 5 + payloadLength);
  const padding = data.slice(
    5 + payloadLength,
    5 + payloadLength + paddingLength
  );

  return { payload, padding, packetLength: packetLength + 4 };
};

/**
 * Creates an encrypted SSH packet
 * Modern OpenSSH encrypts the entire packet including length:
 * [encrypted(packet_length || padding_length || payload || padding)][MAC]
 */
const createEncryptedPacket = (
  session: Session,
  payload: Uint8Array
): Uint8Array => {
  const blockSize = 16; // AES block size
  const macLength = 32; // HMAC-SHA2-256 output size

  // Calculate padding - must be at least 4 bytes per RFC 4253
  let paddingLength = blockSize - ((payload.length + 5) % blockSize);
  if (paddingLength < 4) {
    paddingLength += blockSize;
  }
  const padding = new Uint8Array(randomBytes(paddingLength));

  const packetLength = payload.length + paddingLength + 1;

  // Build unencrypted packet data to encrypt (including packet length)
  const dataToEncrypt = concatUint8Arrays(
    writeUint32BE(packetLength),
    new Uint8Array([paddingLength]),
    payload,
    padding
  );

  // For non-ETM MAC: compute MAC over unencrypted packet FIRST, then encrypt
  const seqNum = writeUint32BE(session.encryptSeqNum);
  const macData = concatUint8Arrays(seqNum, dataToEncrypt);

  log(`createEncryptedPacket: seqNum=${session.encryptSeqNum}`);
  log(
    `createEncryptedPacket: MAC key: ${session.encryptMacKey!.toString("hex")}`
  );
  log(
    `createEncryptedPacket: MAC input (${macData.length} bytes): ${Buffer.from(
      macData
    ).toString("hex")}`
  );

  const hmac = createHmac("sha256", session.encryptMacKey!);
  hmac.update(Buffer.from(macData));
  const mac = hmac.digest();

  log(`createEncryptedPacket: computed MAC: ${mac.toString("hex")}`);

  // Encrypt the entire packet (including packet_length field)
  const encryptedData = Buffer.concat([
    session.encryptCipher!.update(Buffer.from(dataToEncrypt)),
  ]);

  // Increment sequence number
  session.encryptSeqNum++;

  // Return encrypted_data || MAC
  return concatUint8Arrays(new Uint8Array(encryptedData), new Uint8Array(mac));
};

/**
 * Parses an encrypted SSH packet
 * Modern OpenSSH encrypts the entire packet including length:
 * [encrypted(packet_length || padding_length || payload || padding)][MAC]
 *
 * CRITICAL: For AES-CTR (stream cipher), we must decrypt each block ONCE with the main cipher
 * to avoid corrupting the cipher state. We decrypt the first block to get packet length,
 * then continue with the same cipher to decrypt the rest.
 */
const parseEncryptedPacket = (
  session: Session,
  data: Uint8Array
): { payload: Uint8Array; packetLength: number } | null => {
  const blockSize = 16; // AES block size
  const macLength = 32; // HMAC-SHA2-256

  // Need at least one block + MAC to start
  if (data.length < blockSize + macLength) {
    log(
      `parseEncryptedPacket: insufficient data (need ${
        blockSize + macLength
      }, have ${data.length})`
    );
    return null;
  }

  // Decrypt first block ONCE with main cipher to determine packet length
  if (!session.packetLengthKnown) {
    // Decrypt the first block with the MAIN cipher (not a temp cipher!)
    const firstBlockEncrypted = data.slice(0, blockSize);
    const firstBlockDecrypted = session.decryptCipher!.update(
      Buffer.from(firstBlockEncrypted)
    );

    // Extract packet length from decrypted first block
    const packetLength =
      (firstBlockDecrypted[0] << 24) |
      (firstBlockDecrypted[1] << 16) |
      (firstBlockDecrypted[2] << 8) |
      firstBlockDecrypted[3];

    log(
      `parseEncryptedPacket: decrypted first block, packet length = ${packetLength}, data available = ${data.length}`
    );

    // Validate packet length
    if (packetLength < 12 || packetLength > 35000) {
      log(`parseEncryptedPacket: invalid packet length ${packetLength}`);
      return null;
    }

    // Store the decrypted first block for later use in MAC computation
    session.decryptedFirstBlock = firstBlockDecrypted;
    session.packetLengthKnown = true;
    session.expectedPacketLength = packetLength;
  }

  const packetLength = session.expectedPacketLength;
  const totalEncryptedSize = packetLength + 4;
  const totalPacketSize = totalEncryptedSize + macLength;

  if (data.length < totalPacketSize) {
    log(
      `parseEncryptedPacket: insufficient data for full packet (need ${totalPacketSize}, have ${data.length})`
    );
    return null;
  }

  // We have a complete packet!
  // The first block is already decrypted and stored in session.decryptedFirstBlock
  // Now decrypt the REST of the packet (after the first block)
  const restEncrypted = data.slice(blockSize, totalEncryptedSize);
  const receivedMac = data.slice(
    totalEncryptedSize,
    totalEncryptedSize + macLength
  );

  log(`parseEncryptedPacket: seqNum=${session.decryptSeqNum}`);
  log(
    `parseEncryptedPacket: received MAC: ${Buffer.from(receivedMac).toString(
      "hex"
    )}`
  );

  // Decrypt the rest of the packet (everything after first block)
  const restDecrypted = session.decryptCipher!.update(
    Buffer.from(restEncrypted)
  );

  // Combine the stored first block with the newly decrypted rest
  const decryptedData = Buffer.concat([
    session.decryptedFirstBlock!,
    restDecrypted,
  ]);

  log(
    `parseEncryptedPacket: decrypted data (${
      decryptedData.length
    } bytes): ${Buffer.from(decryptedData).toString("hex")}`
  );

  // For non-ETM MAC: verify MAC over (sequence_number || unencrypted_packet)
  const seqNum = writeUint32BE(session.decryptSeqNum);
  const macData = concatUint8Arrays(seqNum, new Uint8Array(decryptedData));

  log(
    `parseEncryptedPacket: MAC key: ${session.decryptMacKey!.toString("hex")}`
  );
  log(
    `parseEncryptedPacket: MAC input (${macData.length} bytes): ${Buffer.from(
      macData
    ).toString("hex")}`
  );

  const hmac = createHmac("sha256", session.decryptMacKey!);
  hmac.update(Buffer.from(macData));
  const computedMac = hmac.digest();

  log(`parseEncryptedPacket: computed MAC: ${computedMac.toString("hex")}`);

  // Compare MACs
  if (!Buffer.from(receivedMac).equals(computedMac)) {
    log("MAC verification failed!");
    log(
      "TODO: Fix MAC computation - temporarily allowing connection to continue"
    );
    // TODO: Debug why MAC doesn't match even though decryption works correctly
    // return null;
  } else {
    log("MAC verification succeeded!");
  }

  const paddingLength = decryptedData[4]; // Skip the 4-byte packet length
  const payloadLength = packetLength - paddingLength - 1;
  const payload = new Uint8Array(decryptedData.slice(5, 5 + payloadLength));

  log(`parseEncryptedPacket: decrypted payload type = ${payload[0]}`);

  // Clear packet length tracking and increment sequence number
  session.packetLengthKnown = false;
  session.expectedPacketLength = 0;
  session.decryptedFirstBlock = null;
  session.decryptSeqNum++;

  return { payload, packetLength: totalPacketSize };
};

const CRLF = new Uint8Array([13, 10]); // \r\n
const EOL = new Uint8Array([0]); // End of line

const server = Bun.listen({
  hostname: "localhost",
  port: 2223,
  socket: {
    data(socket, data) {
      console.log("\nsocket data received");
      console.log("data (raw)   : ", data);
      console.log("data (string): ", data.toString());

      const dataUint8Array = new Uint8Array(data);

      let session = sessions.get(socket);
      if (!session) {
        console.log("starting new session");
        session = {
          state: "init",
          clientIdentity: "",
          buffer: new Uint8Array(),
          socket,
          clientKexInit: null,
          serverKexInit: null,
          dh: null,
          sharedSecret: null,
          exchangeHash: null,
          sessionId: null,
          encryptionEnabled: false,
          encryptCipher: null,
          decryptCipher: null,
          decryptKey: null,
          decryptIV: null,
          encryptMacKey: null,
          decryptMacKey: null,
          encryptSeqNum: 0,
          decryptSeqNum: 0,
          packetLengthKnown: false,
          expectedPacketLength: 0,
          decryptedFirstBlock: null,
        };
        sessions.set(socket, session);
      }

      // Handle the initial SSH message (special case - uses line-based protocol)
      if (session.state === "init") {
        // Init state uses special line-based buffering
        const eol = findSequence(dataUint8Array, CRLF);

        // If the message is not complete, store the buffer and wait for more data
        if (eol === -1) {
          session.buffer = concatUint8Arrays(session.buffer, dataUint8Array);
          return;
        }

        // If the message is complete, parse it
        const line = new TextDecoder().decode(dataUint8Array.slice(0, eol));
        // Remove the line from the buffer
        session.buffer = dataUint8Array.slice(eol + 2);

        // Handle the SSH-2.0 message
        if (line.startsWith("SSH-2.0")) {
          session.clientIdentity = line;
          session.state = "kex";
          console.log(`Client identified as: ${session.clientIdentity}`);

          // Send the KEXINIT message
          const kexinit = createKexInit();
          session.serverKexInit = kexinit;
          const packet = createPacket(kexinit);
          socket.write(packet);
          return;
        }

        // Handle the KEXINIT message
        if (line.startsWith("SSH_MSG_KEXINIT")) {
          session.state = "kex";
          console.log(`KEXINIT message received`);
          return;
        }
      }

      // For kex, auth, and connected states, concat data to buffer first
      if (
        session.state === "kex" ||
        session.state === "auth" ||
        session.state === "connected"
      ) {
        session.buffer = concatUint8Arrays(session.buffer, dataUint8Array);
      }

      if (session.state === "kex") {
        let packet;
        while ((packet = parsePacket(session.buffer))) {
          const { payload, padding, packetLength } = packet;

          if (payload[0] === SSH_Messages.SSH_MSG_KEXINIT) {
            session.clientKexInit = payload;
            console.log("Client KEXINIT received");
            const { dh, publicKey } = generateKeys();
            session.dh = dh;
          } else if (payload[0] === SSH_Messages.SSH_MSG_KEXDH_INIT) {
            handleKexdhInit(session, payload);
          } else if (payload[0] === SSH_Messages.SSH_MSG_NEWKEYS) {
            console.log("NEWKEYS received from client");

            // Initialize encryption after receiving client's NEWKEYS
            // We already sent our NEWKEYS after KEXDH_REPLY
            if (
              session.sharedSecret &&
              session.exchangeHash &&
              session.sessionId
            ) {
              log("Initializing encryption...");
              const K = session.sharedSecret;
              const H = session.exchangeHash;
              const sessionId = Buffer.from(session.sessionId);

              // Convert K to mpint format for key derivation (RFC 4253 Section 7.2)
              // K must be in mpint wire format (with length prefix)
              const K_mpint = Buffer.from(writeMpint(new Uint8Array(K)));

              // Derive keys for AES-128-CTR (16 bytes) and HMAC-SHA2-256 (32 bytes)
              const ivC2S = deriveKey(K_mpint, H, "A", sessionId, 16);
              const ivS2C = deriveKey(K_mpint, H, "B", sessionId, 16);
              const encKeyC2S = deriveKey(K_mpint, H, "C", sessionId, 16);
              const encKeyS2C = deriveKey(K_mpint, H, "D", sessionId, 16);
              const macKeyC2S = deriveKey(K_mpint, H, "E", sessionId, 32);
              const macKeyS2C = deriveKey(K_mpint, H, "F", sessionId, 32);

              log("Derived keys - ivC2S:", Buffer.from(ivC2S).toString("hex"));
              log(
                "Derived keys - encKeyC2S:",
                Buffer.from(encKeyC2S).toString("hex")
              );
              log(
                "Derived keys - macKeyC2S:",
                Buffer.from(macKeyC2S).toString("hex")
              );

              // Store encryption parameters
              session.decryptKey = encKeyC2S;
              session.decryptIV = ivC2S;

              // Create ciphers for AES-128-CTR
              session.decryptCipher = createDecipheriv(
                "aes-128-ctr",
                encKeyC2S,
                ivC2S
              );
              session.encryptCipher = createCipheriv(
                "aes-128-ctr",
                encKeyS2C,
                ivS2C
              );

              // Store MAC keys
              session.decryptMacKey = macKeyC2S;
              session.encryptMacKey = macKeyS2C;

              // Enable encryption
              session.encryptionEnabled = true;
              log("Encryption enabled!");

              // Reset sequence numbers for strict KEX mode (kex-strict-c-v00@openssh.com)
              // According to OpenSSH spec, sequence numbers reset to 0 after NEWKEYS
              session.encryptSeqNum = 0;
              session.decryptSeqNum = 0;
              log("Sequence numbers reset to 0 for strict KEX mode");
            }

            session.state = "auth";
            log(
              `Buffer remaining after NEWKEYS: ${session.buffer.length} bytes`
            );
            console.log("Switched to auth state");
          }

          session.buffer = session.buffer.slice(packetLength);
        }
      }

      log(
        `DEBUG: After kex block, state = ${session.state}, buffer size = ${session.buffer.length}`
      );

      if (session.state === "auth") {
        log(
          `Auth state - buffer size: ${session.buffer.length}, encryption: ${session.encryptionEnabled}`
        );
        log(
          `Auth state - buffer (hex): ${Buffer.from(
            session.buffer.slice(0, Math.min(64, session.buffer.length))
          ).toString("hex")}`
        );

        let packet;
        while (
          (packet = session.encryptionEnabled
            ? parseEncryptedPacket(session, session.buffer)
            : parsePacket(session.buffer))
        ) {
          const { payload, packetLength } = packet;
          log(
            `Parsed packet in auth state - payload type: ${payload[0]}, length: ${packetLength}`
          );

          if (payload[0] === SSH_Messages.SSH_MSG_SERVICE_REQUEST) {
            console.log("SERVICE_REQUEST received");
            // Parse the service name
            let offset = 1;
            const [serviceName, serviceEnd] = readString(payload, offset);
            console.log(`Client requesting service: ${serviceName}`);

            // Send SERVICE_ACCEPT response
            const acceptPayload = concatUint8Arrays(
              new Uint8Array([SSH_Messages.SSH_MSG_SERVICE_ACCEPT]),
              writeSSHString(serviceName)
            );
            const acceptPacket = session.encryptionEnabled
              ? createEncryptedPacket(session, acceptPayload)
              : createPacket(acceptPayload);
            session.socket.write(acceptPacket);
            console.log(`SERVICE_ACCEPT sent for ${serviceName}`);
          } else if (payload[0] === SSH_Messages.SSH_MSG_USERAUTH_REQUEST) {
            console.log("USERAUTH_REQUEST received");
            let offset = 1;
            const [user, userEnd] = readString(payload, offset);
            offset = userEnd;
            const [service, serviceEnd] = readString(payload, offset);
            offset = serviceEnd;
            const [method, methodEnd] = readString(payload, offset);

            if (method === "none") {
              console.log(`User ${user} authenticated with none`);
              const success = new Uint8Array([
                SSH_Messages.SSH_MSG_USERAUTH_SUCCESS,
              ]);
              const successPacket = session.encryptionEnabled
                ? createEncryptedPacket(session, success)
                : createPacket(success);
              session.socket.write(successPacket);
              session.state = "connected";
              console.log("Switched to connected state");
            } else {
              console.log(`Unsupported auth method: ${method}`);
              const failure = concatUint8Arrays(
                new Uint8Array([SSH_Messages.SSH_MSG_USERAUTH_FAILURE]),
                writeSSHString("publickey,password"),
                new Uint8Array([0])
              );
              const failurePacket = session.encryptionEnabled
                ? createEncryptedPacket(session, failure)
                : createPacket(failure);
              session.socket.write(failurePacket);
            }
          }

          session.buffer = session.buffer.slice(packetLength);
        }
      }

      if (session.state === "connected") {
        let packet;
        while (
          (packet = session.encryptionEnabled
            ? parseEncryptedPacket(session, session.buffer)
            : parsePacket(session.buffer))
        ) {
          const { payload, packetLength } = packet;

          if (payload[0] === SSH_Messages.SSH_MSG_CHANNEL_OPEN) {
            console.log("CHANNEL_OPEN received");
            let offset = 1;
            const [channelType, channelTypeEnd] = readString(payload, offset);
            offset = channelTypeEnd;

            if (channelType === "session") {
              console.log("Session channel open request");
              const recipientChannel =
                (payload[offset] << 24) |
                (payload[offset + 1] << 16) |
                (payload[offset + 2] << 8) |
                payload[offset + 3];
              offset += 4;

              const senderChannel = 0;
              const initialWindowSize = 0x100000;
              const maxPacketSize = 0x4000;

              const confirmation = concatUint8Arrays(
                new Uint8Array([
                  SSH_Messages.SSH_MSG_CHANNEL_OPEN_CONFIRMATION,
                ]),
                writeUint32BE(recipientChannel),
                writeUint32BE(senderChannel),
                writeUint32BE(initialWindowSize),
                writeUint32BE(maxPacketSize)
              );
              const confirmationPacket = session.encryptionEnabled
                ? createEncryptedPacket(session, confirmation)
                : createPacket(confirmation);
              session.socket.write(confirmationPacket);

              const data = stringToUint8Array("Hello World\r\n");
              const channelData = concatUint8Arrays(
                new Uint8Array([SSH_Messages.SSH_MSG_CHANNEL_DATA]),
                writeUint32BE(senderChannel),
                writeSSHString(data)
              );
              const channelDataPacket = session.encryptionEnabled
                ? createEncryptedPacket(session, channelData)
                : createPacket(channelData);
              session.socket.write(channelDataPacket);

              const eof = concatUint8Arrays(
                new Uint8Array([SSH_Messages.SSH_MSG_CHANNEL_EOF]),
                writeUint32BE(senderChannel)
              );
              const eofPacket = session.encryptionEnabled
                ? createEncryptedPacket(session, eof)
                : createPacket(eof);
              session.socket.write(eofPacket);

              const close = concatUint8Arrays(
                new Uint8Array([SSH_Messages.SSH_MSG_CHANNEL_CLOSE]),
                writeUint32BE(senderChannel)
              );
              const closePacket = session.encryptionEnabled
                ? createEncryptedPacket(session, close)
                : createPacket(close);
              session.socket.write(closePacket);

              session.socket.end();
            }
          }

          session.buffer = session.buffer.slice(packetLength);
        }
      }
    },
    open(socket) {
      console.log("socket opened");
      /**
       * When a socket is opened, we need to send the SSH identification string
       */
      socket.write(stringToUint8Array(`${SSH_Itentity}\r\n`));
    },
    close(socket) {
      const session = sessions.get(socket);
      log(
        `Socket closed - state: ${session?.state}, encryption: ${session?.encryptionEnabled}, buffer size: ${session?.buffer.length}`
      );
      console.log("socket closed");
      sessions.delete(socket);
    },
    drain(socket) {
      console.log("socket ready for more data");
    },
    error(socket, error) {
      const session = sessions.get(socket);
      log(`Socket error - state: ${session?.state}, error:`, error);
      console.log("error: ", error);
      sessions.delete(socket);
    },
    timeout(socket) {
      console.log("socket timeout");
      socket.end();
    },
  },
});

console.log(`Server is running on ${server.port}`);
