/**
 * Live registration test against the FDMS TEST environment.
 * Uses the device added via the self-service portal (see fdms-test-credentials.md).
 * Writes the issued certificate + private key to ./secrets/ (gitignored).
 */
import { mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { registerDevice, getServerCertificate } from "../src/index.js";
import { NodeTransport } from "../src/node/transport.js";
const device = {
  deviceId: 37367,
  serialNumber: "GOKOSDK001",
  modelName: "Server",
  modelVersion: "v1",
};
const activationKey = "DEVKEY01";

console.log("1) Fetching FDMS server certificate (connectivity check)...");
const chain = await getServerCertificate("test");
console.log(`   OK — got ${chain.length} certificate(s) in chain`);

console.log("2) Generating ECDSA P-256 keys + CSR and registering device...");
try {
  const transport = new NodeTransport(undefined, {
    ca: readFileSync("zimra-simulator-ca.pem", "utf8"),
  });

  const result = await registerDevice(device, activationKey, {
    environment: "test",
    baseUrl: process.env.ZIMRA_BASE_URL || undefined,
    transport,
  });
  console.log(`   OK — operationID: ${result.operationId}`);
  console.log(`   CN used: ${result.keys.commonName}`);

  mkdirSync("secrets", { recursive: true });
  writeFileSync("secrets/device-private-key.pem", result.keys.privateKeyPem);
  writeFileSync("secrets/device-certificate.pem", result.certificatePem);
  console.log("   Saved secrets/device-private-key.pem and device-certificate.pem");
} catch (err) {
  console.error("   Registration failed:", err);
  process.exit(1);
}



