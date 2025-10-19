import { createHmac } from "node:crypto";

// Test MAC computation with values from our logs
const macKey = Buffer.from("a9f5ef337c7383fcdba6c440af00b7efb01d2541580a976b576b6b8f9829d9aa", "hex");
const macInput = Buffer.from("000000000000001c0a050000000c7373682d7573657261757468bd655421f3bdccaced9d", "hex");
const receivedMac = Buffer.from("4555a4b0bb292dae71a0fbeb32d299764e873fbd23137d3ff3186243be428629", "hex");

console.log("MAC Key:", macKey.toString("hex"));
console.log("MAC Input length:", macInput.length);
console.log("MAC Input:", macInput.toString("hex"));

const hmac = createHmac("sha256", macKey);
hmac.update(macInput);
const computed = hmac.digest();

console.log("\nComputed MAC:", computed.toString("hex"));
console.log("Received MAC:", receivedMac.toString("hex"));
console.log("Match:", computed.equals(receivedMac) ? "YES" : "NO");

// Let's also try decoding the MAC input to see what it contains
console.log("\n=== Decoding MAC Input ===");
let offset = 0;
const seqNum = macInput.readUInt32BE(offset);
console.log(`Sequence number: ${seqNum}`);
offset += 4;

const packetLength = macInput.readUInt32BE(offset);
console.log(`Packet length: ${packetLength}`);
offset += 4;

const paddingLength = macInput[offset];
console.log(`Padding length: ${paddingLength}`);
offset += 1;

const messageType = macInput[offset];
console.log(`Message type: ${messageType} (SSH_MSG_SERVICE_REQUEST = 5)`);
offset += 1;

const serviceNameLen = macInput.readUInt32BE(offset);
console.log(`Service name length: ${serviceNameLen}`);
offset += 4;

const serviceName = macInput.slice(offset, offset + serviceNameLen).toString();
console.log(`Service name: "${serviceName}"`);
offset += serviceNameLen;

const padding = macInput.slice(offset);
console.log(`Padding (${padding.length} bytes): ${padding.toString("hex")}`);

console.log(`\nTotal decoded: ${offset + padding.length} bytes`);
console.log(`Expected: ${macInput.length} bytes`);
