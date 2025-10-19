/**
 * SSH Protocol message utilities
 * Handles packet creation, parsing, and message encoding/decoding
 */

import { randomBytes } from "node:crypto";

/**
 * SSH Message Type Constants
 * From RFC 4253 Section 12
 */
export const SSH_MSG = {
  DISCONNECT: 1,
  IGNORE: 2,
  UNIMPLEMENTED: 3,
  DEBUG: 4,
  SERVICE_REQUEST: 5,
  SERVICE_ACCEPT: 6,
  KEXINIT: 20,
  NEWKEYS: 21,
  KEXDH_INIT: 30,
  KEXDH_REPLY: 31,
  USERAUTH_REQUEST: 50,
  USERAUTH_FAILURE: 51,
  USERAUTH_SUCCESS: 52,
  USERAUTH_BANNER: 53,
  GLOBAL_REQUEST: 80,
  REQUEST_SUCCESS: 81,
  REQUEST_FAILURE: 82,
  CHANNEL_OPEN: 90,
  CHANNEL_OPEN_CONFIRMATION: 91,
  CHANNEL_OPEN_FAILURE: 92,
  CHANNEL_WINDOW_ADJUST: 93,
  CHANNEL_DATA: 94,
  CHANNEL_EXTENDED_DATA: 95,
  CHANNEL_EOF: 96,
  CHANNEL_CLOSE: 97,
  CHANNEL_REQUEST: 98,
  CHANNEL_SUCCESS: 99,
  CHANNEL_FAILURE: 100,
} as const;

/**
 * Disconnect reason codes
 */
export const SSH_DISCONNECT = {
  HOST_NOT_ALLOWED_TO_CONNECT: 1,
  PROTOCOL_ERROR: 2,
  KEY_EXCHANGE_FAILED: 3,
  RESERVED: 4,
  MAC_ERROR: 5,
  COMPRESSION_ERROR: 6,
  SERVICE_NOT_AVAILABLE: 7,
  PROTOCOL_VERSION_NOT_SUPPORTED: 8,
  HOST_KEY_NOT_VERIFIABLE: 9,
  CONNECTION_LOST: 10,
  BY_APPLICATION: 11,
  TOO_MANY_CONNECTIONS: 12,
  AUTH_CANCELLED_BY_USER: 13,
  NO_MORE_AUTH_METHODS_AVAILABLE: 14,
  ILLEGAL_USER_NAME: 15,
} as const;

/**
 * Binary data writer for SSH protocol
 */
export class PacketWriter {
  private buffers: Buffer[] = [];

  writeUint8(value: number): this {
    this.buffers.push(Buffer.from([value]));
    return this;
  }

  writeUint32(value: number): this {
    const buf = Buffer.allocUnsafe(4);
    buf.writeUInt32BE(value, 0);
    this.buffers.push(buf);
    return this;
  }

  writeString(str: string | Buffer): this {
    const buf = typeof str === "string" ? Buffer.from(str, "utf8") : str;
    this.writeUint32(buf.length);
    this.buffers.push(buf);
    return this;
  }

  writeBytes(data: Buffer): this {
    this.buffers.push(data);
    return this;
  }

  /**
   * Write a name-list (comma-separated string with length prefix)
   */
  writeNameList(items: string[]): this {
    return this.writeString(items.join(","));
  }

  /**
   * Write an SSH mpint (multiple precision integer)
   */
  writeMPInt(num: Buffer): this {
    // Remove leading zero bytes
    let i = 0;
    while (i < num.length && num[i] === 0) {
      i++;
    }

    const trimmed = num.slice(i);

    // If empty or high bit is set, we need special handling
    if (trimmed.length === 0) {
      this.writeUint32(0);
      return this;
    }

    if (trimmed[0] & 0x80) {
      // High bit is set, prepend zero byte
      this.writeUint32(trimmed.length + 1);
      this.writeUint8(0);
      this.buffers.push(trimmed);
    } else {
      this.writeUint32(trimmed.length);
      this.buffers.push(trimmed);
    }

    return this;
  }

  getBuffer(): Buffer {
    return Buffer.concat(this.buffers);
  }
}

/**
 * Binary data reader for SSH protocol
 */
export class PacketReader {
  private buffer: Buffer;
  private offset: number;

  constructor(buffer: Buffer, offset: number = 0) {
    this.buffer = buffer;
    this.offset = offset;
  }

  readUint8(): number {
    if (this.offset + 1 > this.buffer.length) {
      throw new Error("Buffer overflow");
    }
    const value = this.buffer[this.offset];
    this.offset += 1;
    return value;
  }

  readUint32(): number {
    if (this.offset + 4 > this.buffer.length) {
      throw new Error("Buffer overflow");
    }
    const value = this.buffer.readUInt32BE(this.offset);
    this.offset += 4;
    return value;
  }

  readString(): Buffer {
    const length = this.readUint32();
    if (this.offset + length > this.buffer.length) {
      throw new Error("Buffer overflow");
    }
    const str = this.buffer.slice(this.offset, this.offset + length);
    this.offset += length;
    return str;
  }

  readStringUTF8(): string {
    return this.readString().toString("utf8");
  }

  /**
   * Read a name-list and return as array
   */
  readNameList(): string[] {
    const str = this.readStringUTF8();
    if (str.length === 0) return [];
    return str.split(",");
  }

  /**
   * Read an SSH mpint (multiple precision integer)
   */
  readMPInt(): Buffer {
    const length = this.readUint32();
    if (length === 0) {
      return Buffer.alloc(0);
    }
    if (this.offset + length > this.buffer.length) {
      throw new Error("Buffer overflow");
    }
    const mpint = this.buffer.slice(this.offset, this.offset + length);
    this.offset += length;
    return mpint;
  }

  readBoolean(): boolean {
    return this.readUint8() !== 0;
  }

  readBytes(length: number): Buffer {
    if (this.offset + length > this.buffer.length) {
      throw new Error("Buffer overflow");
    }
    const bytes = this.buffer.slice(this.offset, this.offset + length);
    this.offset += length;
    return bytes;
  }

  getOffset(): number {
    return this.offset;
  }

  getRemainingBytes(): Buffer {
    return this.buffer.slice(this.offset);
  }
}

/**
 * Create an SSH packet with proper padding
 *
 * Packet structure:
 * uint32    packet_length (does not include MAC or this field)
 * byte      padding_length
 * byte[n1]  payload
 * byte[n2]  random padding
 * byte[m]   MAC (added later, not part of packet_length)
 *
 * RFC 4253: The total length of (packet_length || padding_length || payload || padding)
 * must be a multiple of the cipher block size or 8, whichever is larger.
 */
export function createPacket(payload: Buffer, blockSize: number = 8): Buffer {
  // Ensure block size is at least 8
  if (blockSize < 8) blockSize = 8;

  // Minimum padding is 4 bytes
  const minPadding = 4;

  // Calculate padding: we want (4 + 1 + payload.length + padding) % blockSize == 0
  // where 4 is packet_length field, 1 is padding_length field
  let pktLen = 4 + 1 + payload.length;
  let paddingLength = blockSize - (pktLen % blockSize);

  // Ensure minimum padding
  if (paddingLength < minPadding) {
    paddingLength += blockSize;
  }

  // Now pktLen includes padding
  pktLen += paddingLength;

  // packet_length value = pktLen - 4 (excludes the packet_length field itself)
  const packetLengthValue = pktLen - 4;

  // Allocate the full packet
  const packet = Buffer.allocUnsafe(pktLen);

  // Write packet_length (excludes the 4-byte packet_length field itself)
  packet.writeUInt32BE(packetLengthValue, 0);

  // Write padding_length
  packet[4] = paddingLength;

  // Write payload
  payload.copy(packet, 5);

  // Write random padding
  randomBytes(paddingLength).copy(packet, 5 + payload.length);

  return packet;
}

/**
 * Parse an SSH packet
 * Returns the payload (without packet length, padding length, or padding)
 */
export function parsePacket(data: Buffer): { payload: Buffer; rest: Buffer } | null {
  if (data.length < 5) return null;

  const packetLength = data.readUInt32BE(0);

  // Check if we have the complete packet
  if (data.length < 4 + packetLength) {
    return null;
  }

  const paddingLength = data[4];
  const payloadLength = packetLength - paddingLength - 1;

  if (payloadLength < 0) {
    throw new Error("Invalid packet: negative payload length");
  }

  const payload = data.slice(5, 5 + payloadLength);
  const rest = data.slice(4 + packetLength);

  return { payload, rest };
}
