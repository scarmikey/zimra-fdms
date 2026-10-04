import { readFileSync } from "node:fs";
import { FiscalDevice } from "../src/index.js";
import { FdmsClient } from "../src/core/transport.js";
import { NodeTransport } from "../src/node/transport.js";
import { fiscalDaySigningString, signCanonicalString, type EcdsaSignatureFormat } from "../src/core/signing.js";
import { PemSigner } from "../src/node/pem-signer.js";

const device = {
  deviceId: 37367,
  serialNumber: "GOKOSDK001",
  modelName: "Server",
  modelVersion: "v1",
};

const certificatePem = readFileSync("secrets/device-certificate.pem", "utf-8");
const privateKeyPem = readFileSync("secrets/device-private-key.pem", "utf-8");
const ca = readFileSync("zimra-simulator-ca.pem", "utf-8");

const options = {
  environment: "test" as const,
  signatureFormat: "der" as const,
  baseUrl: process.env.ZIMRA_BASE_URL,
  ca,
};

const fd = new FiscalDevice(
  device,
  { certificatePem, privateKeyPem },
  options,
);

console.log("1) GetStatus...");
let status = await fd.getStatus();
console.log(`   ${status.fiscalDayStatus}, day ${status.lastFiscalDayNo}`);

console.log("2) OpenDay...");
const day = await fd.openDay();
console.log(`   opened fiscal day ${day.fiscalDayNo}`);

console.log("3) Submit one valid receipt...");
const receipt = await fd.submitReceipt({
  currency: "USD",
  invoiceNo: `MISMATCH-${Date.now()}`,
  lines: [
    {
      name: "Counter test",
      price: 10,
      quantity: 1,
      taxId: 1,
      taxPercent: 15,
    },
  ],
  payments: [
    { moneyType: "Cash", amount: 10 },
  ],
});
console.log(`   receipt ${receipt.response.receiptID}, errors: ${JSON.stringify(receipt.response.validationErrors ?? [])}`);

console.log("4) Get server counters...");
status = await fd.getStatus();
console.log(`   counters: ${JSON.stringify(status.fiscalDayCounter ?? [])}`);

const fiscalDayNo = status.lastFiscalDayNo!;
const fiscalDayDate = new Date().toISOString().slice(0, 10);
const counters = status.fiscalDayCounter ?? [];

const canonical = fiscalDaySigningString(
  device.deviceId,
  fiscalDayNo,
  fiscalDayDate,
  counters,
);

const signature = await signCanonicalString(
  new PemSigner(privateKeyPem),
  canonical,
  "der" as EcdsaSignatureFormat,
);

const http = new FdmsClient(
  device,
  new NodeTransport(
    { certificatePem, privateKeyPem },
    { ca },
  ),
  {
    environment: "test",
    baseUrl: process.env.ZIMRA_BASE_URL,
  },
);

console.log("5) Sending deliberately WRONG receiptCounter...");
try {
  await http.request(
    "POST",
    `/Device/v1/${device.deviceId}/CloseDay`,
    {
      fiscalDayNo,
      fiscalDayCounters: counters,
      fiscalDayDeviceSignature: signature,
      receiptCounter: 999,
    },
  );
  console.log("   CloseDay accepted.");
} catch (e: any) {
  console.log("   CloseDay request failed:", e.message);
}

await new Promise((r) => setTimeout(r, 1000));

console.log("6) Verify simulator response...");
status = await fd.getStatus();
console.log(`   status: ${status.fiscalDayStatus}`);
console.log(`   closingErrorCode: ${status.fiscalDayClosingErrorCode ?? "none"}`);
