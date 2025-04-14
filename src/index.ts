import { createHash, randomBytes } from "node:crypto";

const SSH_Itentity = "SSH-2.0-BunSSH_0.0.1";

// Connection states
type ConnectionState = "init" | "kex" | "auth" | "connected";

// Session type to track connection state
type Session = {
  state: ConnectionState;
  clientIdentity: string;
  buffer: Uint8Array;
  socket: any;
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
    "aes256-ctr",
    "aes128-ctr",
    "aes256-gcm@openssh.com",
    "aes128-gcm@openssh.com",
    "chacha20-poly1305@openssh.com",
    "aes256-cbc",
    "aes128-cbc",
  ],
  mac: ["hmac-sha2-256", "hmac-sha2-512", "hmac-sha1", "hmac-sha256"],
  compression: [
    "none", // No compression
    "zlib@openssh.com", // Compression after authentication
    "zlib", // Always compress
  ],
} as const;

// Store active sessions
const sessions = new Map<any, Session>();

// Write a 32-bit unsigned integer in big-endian order
const writeUint32BE = (value: number): Uint8Array => {
  const arr = new Uint8Array(4);
  arr[0] = (value >>> 24) & 0xff;
  arr[1] = (value >>> 16) & 0xff;
  arr[2] = (value >>> 8) & 0xff;
  arr[3] = value & 0xff;
  return arr;
};

// Convert a string to a Uint8Array
const stringToUint8Array = (str: string): Uint8Array => {
  return new TextEncoder().encode(str);
};

// Concatenate multiple Uint8Arrays
const concatUint8Arrays = (...arrays: Uint8Array[]): Uint8Array => {
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
  const paddingLength = blockSize - ((payload.length + 5) % blockSize);
  const padding = new Uint8Array(randomBytes(paddingLength));

  const packetLength = payload.length + paddingLength + 1;

  return concatUint8Arrays(
    writeUint32BE(packetLength),
    new Uint8Array([paddingLength]),
    payload,
    padding
  );
};

const CRLF = new Uint8Array([13, 10]); // \r\n
const EOL = new Uint8Array([0]); // End of line

const server = Bun.listen({
  hostname: "localhost",
  port: 2222,
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
        };
        sessions.set(socket, session);
      }

      // Handle the initial SSH message
      if (session.state === "init") {
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
    },
    open(socket) {
      console.log("socket opened");
      /**
       * When a socket is opened, we need to send the SSH identification string
       */
      socket.write(stringToUint8Array(`${SSH_Itentity}\r\n`));
    },
    close(socket) {
      console.log("socket closed");
      sessions.delete(socket);
    },
    drain(socket) {
      console.log("socket ready for more data");
    },
    error(socket, error) {
      console.log("error: ", error);
      sessions.delete(socket);
    },
  },
});

console.log(`Server is running on ${server.port}`);
