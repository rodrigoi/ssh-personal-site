/**
 * Pure TypeScript SSH Server Implementation
 * A minimal, educational SSH server that demonstrates the SSH protocol
 *
 * Protocol Flow:
 * 1. Version string exchange (SSH-2.0-...)
 * 2. Key Exchange (KEXINIT -> KEXDH_INIT -> KEXDH_REPLY -> NEWKEYS)
 * 3. Service Request (usually ssh-userauth)
 * 4. Authentication (simplified - accepts all)
 * 5. Channel Open (session channel)
 * 6. Channel Requests (shell, exec, etc.)
 * 7. Channel Data exchange
 * 8. Channel Close
 */

import {
  AES128CTR,
  DHGroup14Exchange,
  HMACSHA256,
  deriveKey,
  signData,
} from "./crypto-utils";
import {
  PacketReader,
  PacketWriter,
  SSH_DISCONNECT,
  SSH_MSG,
  createPacket,
  parsePacket,
} from "./protocol";

import type { HostKeyPair } from "./host-key";
import { createHash } from "node:crypto";

// Server identification string
const SERVER_IDENT = "SSH-2.0-BunTypeScript_1.0";

// Algorithm preferences (simplified for education)
const ALGORITHMS = {
  kex: ["diffie-hellman-group14-sha256"],
  hostKey: ["ssh-ed25519"],
  encryption: ["aes128-ctr"],
  mac: ["hmac-sha2-256"],
  compression: ["none"],
} as const;

/**
 * Connection state machine
 */
type ConnectionState =
  | "version_exchange"
  | "kex_init"
  | "kex_dh"
  | "new_keys"
  | "service_request"
  | "userauth"
  | "authenticated"
  | "session"
  | "closed";

/**
 * SSH Channel for managing communication
 */
interface Channel {
  clientChannel: number;
  serverChannel: number;
  windowSize: number;
  maxPacketSize: number;
}

/**
 * SSH Connection Session
 */
export class SSHSession {
  private state: ConnectionState = "version_exchange";
  private buffer: Buffer = Buffer.alloc(0);
  private socket: any;

  // Version exchange
  private clientVersion: string = "";
  private clientVersionRaw: Buffer = Buffer.alloc(0);
  private serverVersionRaw: Buffer = Buffer.from(`${SERVER_IDENT}\r\n`);

  // Key exchange
  private clientKexInit: Buffer | null = null;
  private serverKexInit: Buffer | null = null;
  private dhExchange: DHGroup14Exchange | null = null;
  private sessionId: Buffer | null = null;
  private sharedSecret: Buffer | null = null;
  private exchangeHash: Buffer | null = null;

  // Host key (shared across all sessions)
  private hostKeyPair: HostKeyPair;

  // Encryption state
  private encrypted = false;
  private cipher: AES128CTR | null = null;
  private mac: HMACSHA256 | null = null;
  private inSeqNum = 0;
  private outSeqNum = 0;

  // Channel state
  private channels = new Map<number, Channel>();
  private nextServerChannel = 0;
  private activeChannel: number | null = null; // Track the interactive channel

  constructor(socket: any, hostKeyPair: HostKeyPair) {
    this.socket = socket;
    this.hostKeyPair = hostKeyPair;
  }

  /**
   * Handle incoming data from the client
   */
  handleData(data: Buffer) {
    this.buffer = Buffer.concat([this.buffer, data]);

    try {
      this.processBuffer();
    } catch (err) {
      console.error("Error processing buffer:", err);
      this.disconnect(SSH_DISCONNECT.PROTOCOL_ERROR, "Protocol error");
    }
  }

  /**
   * Process the buffer based on current state
   */
  private processBuffer() {
    try {
      // In version exchange, look for \r\n terminated string
      if (this.state === "version_exchange") {
        const idx = this.buffer.indexOf("\r\n");
        if (idx === -1) return; // Need more data

        // Store both string and raw bytes (without CRLF for string, with for raw)
        this.clientVersionRaw = this.buffer.slice(0, idx + 2);
        this.clientVersion = this.buffer.slice(0, idx).toString("utf8");
        this.buffer = this.buffer.slice(idx + 2);

        console.log(`Client version: ${this.clientVersion}`);

        // Send our KEXINIT immediately after version exchange
        this.state = "kex_init";
        this.sendKexInit();

        // Continue processing
        this.processBuffer();
        return;
      }

      // All other messages are binary packets
      while (this.buffer.length > 0) {
        const result = this.readPacket();
        if (!result) return; // Need more data

        const { payload } = result;

        // Process the message
        this.handleMessage(payload);
      }
    } catch (err) {
      console.error("Error in processBuffer:", err);
      throw err;
    }
  }

  /**
   * Read and decrypt a packet from the buffer
   */
  private readPacket(): { payload: Buffer } | null {
    if (!this.encrypted) {
      // Unencrypted packet
      const result = parsePacket(this.buffer);
      if (!result) return null;

      this.buffer = result.rest;
      this.inSeqNum++;
      return { payload: result.payload };
    } else {
      // Encrypted packet with MAC (non-ETM mode)
      // Packet structure: encrypted(packet_length || padding_length || payload || padding) || MAC
      //
      // For standard (non-ETM) MAC, we must:
      // 1. Decrypt the packet
      // 2. Compute MAC on the DECRYPTED data
      // 3. Compare with received MAC

      const blockSize = 16; // AES block size
      const macLength = 32; // SHA256 MAC length

      // Need at least one block to get started
      if (this.buffer.length < blockSize) return null;

      // Decrypt the first block to get packet length
      const firstBlock = this.buffer.slice(0, blockSize);
      const decryptedFirstBlock = this.cipher!.decrypt(firstBlock);

      // Extract packet length from first 4 bytes of decrypted data
      const packetLength = decryptedFirstBlock.readUInt32BE(0);

      // Validate packet length
      if (packetLength < 12 || packetLength > 35000) {
        throw new Error(`Invalid packet length: ${packetLength}`);
      }

      // Calculate full packet size (including the 4-byte length field)
      const fullEncryptedSize = 4 + packetLength;
      const fullPacketSize = fullEncryptedSize + macLength;

      // Check if we have the complete packet
      if (this.buffer.length < fullPacketSize) {
        // We don't have enough data yet, but we already decrypted the first block!
        // This is a problem - we can't "un-decrypt" it.
        // For a proper implementation, we'd need to buffer the decrypted block.
        // For now, this is a known limitation.
        throw new Error(
          "Partial packet read after decrypting first block - not supported"
        );
      }

      // Extract the encrypted packet and MAC
      const encryptedPacket = this.buffer.slice(0, fullEncryptedSize);
      const receivedMAC = this.buffer.slice(fullEncryptedSize, fullPacketSize);
      this.buffer = this.buffer.slice(fullPacketSize);

      // Decrypt the remaining part of the packet (we already decrypted the first block)
      const restEncrypted = encryptedPacket.slice(blockSize);
      const decryptedRest =
        restEncrypted.length > 0
          ? this.cipher!.decrypt(restEncrypted)
          : Buffer.alloc(0);

      // Combine decrypted blocks to get the full decrypted packet
      const decryptedPacket = Buffer.concat([decryptedFirstBlock, decryptedRest]);

      // For non-ETM MAC, verify MAC on the DECRYPTED packet
      if (!this.mac!.verifyMAC(this.inSeqNum, decryptedPacket, receivedMAC)) {
        console.error(`MAC verification failed for packet ${this.inSeqNum}`);
        console.error(`Packet length: ${packetLength}, Full size: ${fullPacketSize}`);
        throw new Error("MAC verification failed");
      }

      // Parse the packet structure
      const paddingLength = decryptedPacket[4];
      const payloadLength = packetLength - paddingLength - 1;

      if (payloadLength < 0 || payloadLength > packetLength) {
        throw new Error(`Invalid payload length: ${payloadLength}`);
      }

      const payload = decryptedPacket.slice(5, 5 + payloadLength);

      this.inSeqNum++;
      return { payload };
    }
  }

  /**
   * Handle a decrypted message payload
   */
  private handleMessage(payload: Buffer) {
    if (payload.length === 0) return;

    const msgType = payload[0];
    console.log(
      `Received message type: ${msgType} (${this.getMsgName(msgType)})`
    );

    switch (msgType) {
      case SSH_MSG.KEXINIT:
        this.handleKexInit(payload);
        break;
      case SSH_MSG.KEXDH_INIT:
        this.handleKexDhInit(payload);
        break;
      case SSH_MSG.NEWKEYS:
        this.handleNewKeys();
        break;
      case SSH_MSG.SERVICE_REQUEST:
        this.handleServiceRequest(payload);
        break;
      case SSH_MSG.USERAUTH_REQUEST:
        this.handleUserAuthRequest(payload);
        break;
      case SSH_MSG.CHANNEL_OPEN:
        this.handleChannelOpen(payload);
        break;
      case SSH_MSG.CHANNEL_REQUEST:
        this.handleChannelRequest(payload);
        break;
      case SSH_MSG.CHANNEL_DATA:
        this.handleChannelData(payload);
        break;
      case SSH_MSG.CHANNEL_EOF:
        this.handleChannelEOF(payload);
        break;
      case SSH_MSG.CHANNEL_CLOSE:
        this.handleChannelClose(payload);
        break;
      default:
        console.log(`Unhandled message type: ${msgType}`);
        // Send UNIMPLEMENTED
        this.sendUnimplemented();
    }
  }

  /**
   * Send KEXINIT message
   */
  private sendKexInit() {
    const writer = new PacketWriter();

    writer.writeUint8(SSH_MSG.KEXINIT);

    // 16 random bytes (cookie)
    writer.writeBytes(require("node:crypto").randomBytes(16));

    // Algorithm lists
    writer.writeNameList(ALGORITHMS.kex);
    writer.writeNameList(ALGORITHMS.hostKey);
    writer.writeNameList(ALGORITHMS.encryption); // client_to_server
    writer.writeNameList(ALGORITHMS.encryption); // server_to_client
    writer.writeNameList(ALGORITHMS.mac); // client_to_server
    writer.writeNameList(ALGORITHMS.mac); // server_to_client
    writer.writeNameList(ALGORITHMS.compression); // client_to_server
    writer.writeNameList(ALGORITHMS.compression); // server_to_client
    writer.writeNameList([]); // languages client_to_server
    writer.writeNameList([]); // languages server_to_client

    writer.writeUint8(0); // first_kex_packet_follows = false
    writer.writeUint32(0); // reserved

    const payload = writer.getBuffer();
    this.serverKexInit = payload;

    this.sendPacket(payload);
    console.log("Sent KEXINIT");
  }

  /**
   * Handle KEXINIT message from client
   */
  private handleKexInit(payload: Buffer) {
    this.clientKexInit = payload;
    console.log("Received KEXINIT from client");

    // Parse client algorithms (simplified - we'll just accept our preferred)
    const reader = new PacketReader(payload, 1); // Skip message type

    // Skip cookie (16 bytes)
    reader.readBytes(16);

    // Read algorithm lists
    const kexAlgs = reader.readNameList();
    const hostKeyAlgs = reader.readNameList();
    const cipherC2S = reader.readNameList();
    const cipherS2C = reader.readNameList();
    const macC2S = reader.readNameList();
    const macS2C = reader.readNameList();

    console.log("Client algorithms:", {
      kex: kexAlgs,
      hostKey: hostKeyAlgs,
      cipher: cipherC2S,
      mac: macC2S,
    });

    // Initialize DH exchange
    this.dhExchange = new DHGroup14Exchange();
    this.state = "kex_dh";
  }

  /**
   * Handle KEXDH_INIT message (client's DH public key)
   */
  private handleKexDhInit(payload: Buffer) {
    if (!this.dhExchange) {
      throw new Error("DH exchange not initialized");
    }

    const reader = new PacketReader(payload, 1); // Skip message type
    const clientPublicKey = reader.readMPInt();

    console.log("Received client DH public key");

    // Compute shared secret
    const sharedSecret = this.dhExchange.computeSecret(clientPublicKey);
    this.sharedSecret = sharedSecret;

    // Build KEXDH_REPLY message
    this.sendKexDhReply(clientPublicKey);

    this.state = "new_keys";
  }

  /**
   * Send KEXDH_REPLY message
   */
  private sendKexDhReply(clientPublicKey: Buffer) {
    if (!this.dhExchange || !this.sharedSecret) {
      throw new Error("DH exchange not completed");
    }

    const serverPublicKey = this.dhExchange.getPublicKey();

    // Encode host public key in SSH format
    // Ed25519 public key is 32 bytes raw
    const publicKeyRaw = this.hostKeyPair.publicKey.export({
      type: "spki",
      format: "der",
    });

    // Extract the 32-byte Ed25519 public key from the DER format
    // DER format for Ed25519 has the 32-byte public key at the end
    const ed25519PublicKey = publicKeyRaw.slice(-32);

    const hostKeyWriter = new PacketWriter();
    hostKeyWriter.writeString("ssh-ed25519");
    hostKeyWriter.writeString(ed25519PublicKey);
    const hostKeyBytes = hostKeyWriter.getBuffer();

    // Compute exchange hash H
    const exchangeHash = this.computeExchangeHash(
      clientPublicKey,
      serverPublicKey,
      hostKeyBytes
    );

    this.exchangeHash = exchangeHash;

    // Session ID is the first exchange hash
    if (!this.sessionId) {
      this.sessionId = exchangeHash;
    }

    // Sign the exchange hash
    const signature = signData(this.hostKeyPair.privateKey, exchangeHash);

    // Build signature blob
    const sigWriter = new PacketWriter();
    sigWriter.writeString("ssh-ed25519");
    sigWriter.writeString(signature);
    const signatureBlob = sigWriter.getBuffer();

    // Build KEXDH_REPLY
    const writer = new PacketWriter();
    writer.writeUint8(SSH_MSG.KEXDH_REPLY);
    writer.writeString(hostKeyBytes); // K_S (host key)
    writer.writeMPInt(serverPublicKey); // f (server DH public key)
    writer.writeString(signatureBlob); // signature of H

    this.sendPacket(writer.getBuffer());
    console.log("Sent KEXDH_REPLY");

    // Send NEWKEYS
    this.sendNewKeys();
  }

  /**
   * Compute the exchange hash H
   * According to RFC 4253 Section 8
   */
  private computeExchangeHash(
    clientPublicKey: Buffer,
    serverPublicKey: Buffer,
    hostKeyBytes: Buffer
  ): Buffer {
    const hash = createHash("sha256");

    // Helper to write string with length prefix
    const hashString = (buf: Buffer) => {
      const len = Buffer.allocUnsafe(4);
      len.writeUInt32BE(buf.length, 0);
      hash.update(len);
      hash.update(buf);
    };

    // V_C (client version string - without CRLF)
    const clientVersionBuf = Buffer.from(this.clientVersion, "utf8");
    hashString(clientVersionBuf);

    // V_S (server version string - without CRLF)
    const serverVersionBuf = Buffer.from(SERVER_IDENT, "utf8");
    hashString(serverVersionBuf);

    // I_C (client KEXINIT payload)
    hashString(this.clientKexInit!);

    // I_S (server KEXINIT payload)
    hashString(this.serverKexInit!);

    // K_S (host public key)
    hashString(hostKeyBytes);

    // e (client DH public key as mpint)
    const writer1 = new PacketWriter();
    writer1.writeMPInt(clientPublicKey);
    hash.update(writer1.getBuffer());

    // f (server DH public key as mpint)
    const writer2 = new PacketWriter();
    writer2.writeMPInt(serverPublicKey);
    hash.update(writer2.getBuffer());

    // K (shared secret as mpint)
    const writer3 = new PacketWriter();
    writer3.writeMPInt(this.sharedSecret!);
    hash.update(writer3.getBuffer());

    return hash.digest();
  }

  /**
   * Send NEWKEYS message
   */
  private sendNewKeys() {
    const writer = new PacketWriter();
    writer.writeUint8(SSH_MSG.NEWKEYS);
    this.sendPacket(writer.getBuffer());
    console.log("Sent NEWKEYS");
  }

  /**
   * Handle NEWKEYS message from client
   * After this, all communication is encrypted
   */
  private handleNewKeys() {
    console.log("Received NEWKEYS");

    // Derive encryption keys
    if (!this.exchangeHash || !this.sessionId || !this.sharedSecret) {
      throw new Error("Cannot derive keys: missing KEX data");
    }

    // Key derivation: HASH(K || H || X || session_id)
    // where X is a character from 'A' to 'F' for different keys

    // IV client to server (A)
    const ivC2S = deriveKey(
      this.sharedSecret,
      this.exchangeHash,
      "A",
      this.sessionId,
      16
    );

    // IV server to client (B)
    const ivS2C = deriveKey(
      this.sharedSecret,
      this.exchangeHash,
      "B",
      this.sessionId,
      16
    );

    // Encryption key client to server (C)
    const keyC2S = deriveKey(
      this.sharedSecret,
      this.exchangeHash,
      "C",
      this.sessionId,
      16
    );

    // Encryption key server to client (D)
    const keyS2C = deriveKey(
      this.sharedSecret,
      this.exchangeHash,
      "D",
      this.sessionId,
      16
    );

    // MAC key client to server (E)
    const macC2S = deriveKey(
      this.sharedSecret,
      this.exchangeHash,
      "E",
      this.sessionId,
      32
    );

    // MAC key server to client (F)
    const macS2C = deriveKey(
      this.sharedSecret,
      this.exchangeHash,
      "F",
      this.sessionId,
      32
    );

    // Initialize cipher and MAC
    this.cipher = new AES128CTR(keyS2C, ivS2C, keyC2S, ivC2S);
    this.mac = new HMACSHA256(macS2C, macC2S);

    // Enable encryption
    this.encrypted = true;

    // NOTE: Sequence numbers do NOT reset! They continue from the unencrypted phase.
    // Each packet (encrypted or not) increments the sequence number.
    console.log(`Encryption enabled at seq in=${this.inSeqNum}, out=${this.outSeqNum}`);

    this.state = "service_request";
  }

  /**
   * Handle SERVICE_REQUEST (typically "ssh-userauth")
   */
  private handleServiceRequest(payload: Buffer) {
    const reader = new PacketReader(payload, 1);
    const serviceName = reader.readStringUTF8();

    console.log(`Service requested: ${serviceName}`);

    // Accept the service
    const writer = new PacketWriter();
    writer.writeUint8(SSH_MSG.SERVICE_ACCEPT);
    writer.writeString(serviceName);
    this.sendPacket(writer.getBuffer());

    this.state = "userauth";
    console.log("Sent SERVICE_ACCEPT");
  }

  /**
   * Handle USERAUTH_REQUEST
   * Simplified: accept all authentication attempts
   */
  private handleUserAuthRequest(payload: Buffer) {
    const reader = new PacketReader(payload, 1);
    const username = reader.readStringUTF8();
    const service = reader.readStringUTF8();
    const method = reader.readStringUTF8();

    console.log(
      `Auth request: user=${username}, service=${service}, method=${method}`
    );

    // Accept all authentication (simplified for demo)
    const writer = new PacketWriter();
    writer.writeUint8(SSH_MSG.USERAUTH_SUCCESS);
    this.sendPacket(writer.getBuffer());

    this.state = "authenticated";
    console.log("Sent USERAUTH_SUCCESS");
  }

  /**
   * Handle CHANNEL_OPEN request
   */
  private handleChannelOpen(payload: Buffer) {
    const reader = new PacketReader(payload, 1);
    const channelType = reader.readStringUTF8();
    const clientChannel = reader.readUint32();
    const initialWindowSize = reader.readUint32();
    const maxPacketSize = reader.readUint32();

    console.log(
      `Channel open: type=${channelType}, client_channel=${clientChannel}, ` +
        `window=${initialWindowSize}, max_packet=${maxPacketSize}`
    );

    // Create server channel
    const serverChannel = this.nextServerChannel++;
    this.channels.set(serverChannel, {
      clientChannel,
      serverChannel,
      windowSize: initialWindowSize,
      maxPacketSize,
    });

    // Send CHANNEL_OPEN_CONFIRMATION
    const writer = new PacketWriter();
    writer.writeUint8(SSH_MSG.CHANNEL_OPEN_CONFIRMATION);
    writer.writeUint32(clientChannel); // recipient channel
    writer.writeUint32(serverChannel); // sender channel
    writer.writeUint32(32768); // initial window size
    writer.writeUint32(32768); // maximum packet size
    this.sendPacket(writer.getBuffer());

    this.state = "session";
    console.log("Sent CHANNEL_OPEN_CONFIRMATION");
  }

  /**
   * Handle CHANNEL_REQUEST (pty-req, shell, exec, etc.)
   */
  private handleChannelRequest(payload: Buffer) {
    const reader = new PacketReader(payload, 1);
    const recipientChannel = reader.readUint32();
    const requestType = reader.readStringUTF8();
    const wantReply = reader.readBoolean();

    console.log(
      `Channel request: channel=${recipientChannel}, type=${requestType}, want_reply=${wantReply}`
    );

    // Accept all channel requests
    if (wantReply) {
      const writer = new PacketWriter();
      writer.writeUint8(SSH_MSG.CHANNEL_SUCCESS);
      writer.writeUint32(recipientChannel);
      this.sendPacket(writer.getBuffer());
    }

    // If this is a shell or exec request, send our "Hello World" message
    if (requestType === "shell" || requestType === "exec") {
      this.sendHelloWorld(recipientChannel);
    }
  }

  /**
   * Send "Hello World" message and wait for input
   */
  private sendHelloWorld(recipientChannel: number) {
    console.log("Sending Hello World message");

    // Store the active channel for interaction
    this.activeChannel = recipientChannel;

    // Send channel data with rainbow colors (ANSI escape codes)
    // Add an empty second line for the status updates
    const message =
      "\x1b[91mH" +  // bright red
      "\x1b[93me" +  // bright yellow
      "\x1b[92ml" +  // bright green
      "\x1b[96ml" +  // bright cyan
      "\x1b[94mo" +  // bright blue
      "\x1b[0m " +   // space (reset color)
      "\x1b[95mW" +  // bright magenta
      "\x1b[91mo" +  // bright red
      "\x1b[93mr" +  // bright yellow
      "\x1b[92ml" +  // bright green
      "\x1b[96md" +  // bright cyan
      "\x1b[0m\r\n" + // reset color
      "\r\n";        // empty line for status
    const writer = new PacketWriter();
    writer.writeUint8(SSH_MSG.CHANNEL_DATA);
    writer.writeUint32(recipientChannel);
    writer.writeString(message);
    this.sendPacket(writer.getBuffer());

    console.log("Sent Hello World, waiting for input...");
  }

  /**
   * Update the status line (line below Hello World) with new text
   */
  private updateStatusLine(recipientChannel: number, text: string) {
    // Use ANSI escape codes to:
    // 1. Move cursor up one line: \x1b[1A
    // 2. Clear the entire line: \x1b[2K
    // 3. Return to beginning: \r
    // 4. Write the new text
    // 5. Move to next line: \r\n
    const message = "\x1b[1A\x1b[2K\r" + text + "\r\n";

    const writer = new PacketWriter();
    writer.writeUint8(SSH_MSG.CHANNEL_DATA);
    writer.writeUint32(recipientChannel);
    writer.writeString(message);
    this.sendPacket(writer.getBuffer());

    console.log(`Updated status line: ${text}`);
  }

  /**
   * Send animated "Goodbye" message with brightness pulse for 10 seconds, then close
   */
  private sendGoodbye(recipientChannel: number) {
    console.log("Starting Goodbye animation");

    // Clear the active channel to prevent further input
    this.activeChannel = null;

    // Animation parameters
    const duration = 10000; // 10 seconds
    const interval = 50;    // 50ms between frames (smooth animation)
    const totalFrames = duration / interval; // 200 frames
    let frame = 0;

    // Start the brightness pulse animation
    const animationInterval = setInterval(() => {
      // Calculate brightness using sine wave for smooth pulsing
      // Goes from 0 to 1 and back (one complete pulse cycle every ~2 seconds)
      const phase = (frame / totalFrames) * Math.PI * 5; // 5 complete pulses over 10 seconds
      const brightness = (Math.sin(phase) + 1) / 2; // Convert -1...1 to 0...1

      // Create "Goodbye" with brightness based on sine wave
      // Use 8 brightness levels from very dim to very bright
      const level = Math.floor(brightness * 7);
      let goodbye: string;

      switch (level) {
        case 0:
          goodbye = "\x1b[2m\x1b[30mGoodbye\x1b[0m"; // very dim black
          break;
        case 1:
          goodbye = "\x1b[2m\x1b[37mGoodbye\x1b[0m"; // dim white
          break;
        case 2:
          goodbye = "\x1b[37mGoodbye\x1b[0m";        // normal white
          break;
        case 3:
          goodbye = "\x1b[97mGoodbye\x1b[0m";        // bright white
          break;
        case 4:
          goodbye = "\x1b[1m\x1b[97mGoodbye\x1b[0m"; // bold bright white
          break;
        case 5:
          goodbye = "\x1b[1m\x1b[93mGoodbye\x1b[0m"; // bold bright yellow
          break;
        case 6:
          goodbye = "\x1b[1m\x1b[91mGoodbye\x1b[0m"; // bold bright red
          break;
        default:
          goodbye = "\x1b[1m\x1b[95mGoodbye\x1b[0m"; // bold bright magenta (peak)
          break;
      }

      // Update the status line
      const message = "\x1b[1A\x1b[2K\r" + goodbye + "\r\n";
      const writer = new PacketWriter();
      writer.writeUint8(SSH_MSG.CHANNEL_DATA);
      writer.writeUint32(recipientChannel);
      writer.writeString(message);
      this.sendPacket(writer.getBuffer());

      frame++;
    }, interval);

    // After 10 seconds, stop animation and close channel
    setTimeout(() => {
      clearInterval(animationInterval);

      // Send final bright goodbye
      const finalGoodbye = "\x1b[1m\x1b[95mGoodbye\x1b[0m";
      const message = "\x1b[1A\x1b[2K\r" + finalGoodbye + "\r\n";
      const writer = new PacketWriter();
      writer.writeUint8(SSH_MSG.CHANNEL_DATA);
      writer.writeUint32(recipientChannel);
      writer.writeString(message);
      this.sendPacket(writer.getBuffer());

      // Send EOF
      const writerEOF = new PacketWriter();
      writerEOF.writeUint8(SSH_MSG.CHANNEL_EOF);
      writerEOF.writeUint32(recipientChannel);
      this.sendPacket(writerEOF.getBuffer());

      // Close the channel
      const writerClose = new PacketWriter();
      writerClose.writeUint8(SSH_MSG.CHANNEL_CLOSE);
      writerClose.writeUint32(recipientChannel);
      this.sendPacket(writerClose.getBuffer());

      console.log("Animation complete, channel closed");
    }, duration);
  }

  /**
   * Handle CHANNEL_DATA (user keyboard input)
   */
  private handleChannelData(payload: Buffer) {
    const reader = new PacketReader(payload, 1);
    const recipientChannel = reader.readUint32();
    const data = reader.readString();

    console.log(`Received channel data: ${Buffer.from(data).toString("hex")}`);

    // Only handle input if this is the active channel
    if (recipientChannel !== this.activeChannel) {
      return;
    }

    const input = data.toString();

    // Detect arrow keys (escape sequences)
    // Arrow keys send: ESC [ <letter>
    // Right: \x1b[C or \x1b[OC
    // Left: \x1b[D or \x1b[OD
    // Up: \x1b[A or \x1b[OA
    // Down: \x1b[B or \x1b[OB

    if (input === "\x1b[C" || input === "\x1b[OC") {
      this.updateStatusLine(recipientChannel, "\x1b[92mright arrow\x1b[0m"); // green
    } else if (input === "\x1b[D" || input === "\x1b[OD") {
      this.updateStatusLine(recipientChannel, "\x1b[93mleft arrow\x1b[0m");  // yellow
    } else if (input === "\x1b[A" || input === "\x1b[OA") {
      this.updateStatusLine(recipientChannel, "\x1b[94mup arrow\x1b[0m");    // blue
    } else if (input === "\x1b[B" || input === "\x1b[OB") {
      this.updateStatusLine(recipientChannel, "\x1b[91mdown arrow\x1b[0m");  // red
    } else {
      // Any other key - send rainbow goodbye and close
      this.sendGoodbye(recipientChannel);
    }
  }

  /**
   * Handle CHANNEL_EOF
   */
  private handleChannelEOF(payload: Buffer) {
    const reader = new PacketReader(payload, 1);
    const recipientChannel = reader.readUint32();
    console.log(`Received channel EOF for channel ${recipientChannel}`);
  }

  /**
   * Handle CHANNEL_CLOSE
   */
  private handleChannelClose(payload: Buffer) {
    const reader = new PacketReader(payload, 1);
    const recipientChannel = reader.readUint32();
    console.log(`Received channel close for channel ${recipientChannel}`);

    // Clean up channel
    this.channels.delete(recipientChannel);

    // Close connection
    this.socket.end();
  }

  /**
   * Send a disconnect message
   */
  private disconnect(reason: number, description: string) {
    console.log(`Disconnecting: ${description}`);

    const writer = new PacketWriter();
    writer.writeUint8(SSH_MSG.DISCONNECT);
    writer.writeUint32(reason);
    writer.writeString(description);
    writer.writeString(""); // language tag

    this.sendPacket(writer.getBuffer());
    this.socket.end();
  }

  /**
   * Send an unimplemented message
   */
  private sendUnimplemented() {
    const writer = new PacketWriter();
    writer.writeUint8(SSH_MSG.UNIMPLEMENTED);
    writer.writeUint32(this.inSeqNum - 1);
    this.sendPacket(writer.getBuffer());
  }

  /**
   * Send a packet (handles encryption if enabled)
   */
  private sendPacket(payload: Buffer) {
    const packet = createPacket(payload, this.encrypted ? 16 : 8);

    if (!this.encrypted) {
      // Send unencrypted
      this.socket.write(packet);
      this.outSeqNum++;
    } else {
      // For non-ETM MAC: compute MAC on UNENCRYPTED packet, then encrypt
      const mac = this.mac!.computeMAC(this.outSeqNum, packet);
      const encrypted = this.cipher!.encrypt(packet);

      this.socket.write(Buffer.concat([encrypted, mac]));
      this.outSeqNum++;
    }
  }

  /**
   * Get message name for logging
   */
  private getMsgName(type: number): string {
    for (const [name, value] of Object.entries(SSH_MSG)) {
      if (value === type) return name;
    }
    return "UNKNOWN";
  }

  /**
   * Start the session (send version string)
   */
  start() {
    this.socket.write(`${SERVER_IDENT}\r\n`);
    console.log(`Sent version: ${SERVER_IDENT}`);
  }
}

/**
 * Create and start the SSH server
 */
export function createSSHServer(port: number = 2222, hostKeyPair: HostKeyPair) {
  const server = Bun.listen({
    hostname: "localhost",
    port,
    socket: {
      data(socket, data) {
        const session = (socket as any).sshSession as SSHSession;
        session.handleData(Buffer.from(data));
      },
      open(socket) {
        console.log("\n=== New SSH connection ===");
        const session = new SSHSession(socket, hostKeyPair);
        (socket as any).sshSession = session;
        session.start();
      },
      close(socket) {
        console.log("=== Connection closed ===\n");
      },
      error(socket, error) {
        console.error("Socket error:", error);
      },
    },
  });

  console.log(`SSH Server listening on port ${server.port}`);
  return server;
}
