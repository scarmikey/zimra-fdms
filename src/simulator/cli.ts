#!/usr/bin/env node
/**
 * zimra-fdms-simulator: run a local FDMS from the command line.
 *
 *   npx zimra-fdms-simulator --port 8443 --ca ./sim-ca.pem
 *
 * Then point the SDK or the CLI at it:
 *
 *   ZIMRA_BASE_URL=https://localhost:8443 ZIMRA_CA=./sim-ca.pem zimra-fdms register ...
 */
import { parseArgs } from "node:util";
import { FdmsSimulator } from "./server.js";
import { SimulatorCa } from "./ca.js";

const { values } = parseArgs({
  options: {
    port: { type: "string", default: "8443" },
    host: { type: "string", default: "127.0.0.1" },
    ca: { type: "string", short: "c", default: ".simulator-state/zimra-simulator-ca.pem" },
    "ca-key": { type: "string", default: ".simulator-state/zimra-simulator-ca-key.pem" },
    "activation-key": { type: "string", multiple: true },
    "close-delay": { type: "string", default: "300" },
    "initial-fiscal-day": { type: "string", default: "0" },
    "initial-global-no": { type: "string", default: "0" },
    "initial-receipt-counter": { type: "string", default: "0" },
    "initial-previous-receipt-hash": { type: "string", default: "" },
    san: { type: "string", multiple: true },
    help: { type: "boolean", short: "h" },
  },
});

if (values.help) {
  console.log(`zimra-fdms-simulator: a local FDMS with real mutual TLS.

Options
  --port <n>              Listen port (default 8443)
  --host <addr>           Bind address (default 127.0.0.1)
  --ca <file>             CA certificate path\n  --ca-key <file>         CA private key path (keep private)
  --activation-key <key>  Accept only these keys for RegisterDevice (repeatable; default any 8 chars)
  --close-delay <ms>      Time before CloseDay settles (default 300)
  --initial-fiscal-day <n> Start simulator with this fiscal day already open
  --initial-global-no <n>  Seed the historical receipt global number
  --initial-receipt-counter <n> Seed the previous receipt counter
  --initial-previous-receipt-hash <hash> Seed the previous receipt hash
  --san <name-or-ip>      Extra subject alternative name for the server certificate
                          (repeatable; --host 0.0.0.0 --san 10.0.2.2 for an Android emulator)

The SDK needs the CA to trust the server:
  new FiscalDevice(id, pems, { baseUrl: "https://localhost:8443", ca: readFileSync(".simulator-state/zimra-simulator-ca.pem", "utf-8") })
The CLI reads ZIMRA_BASE_URL and ZIMRA_CA.`);
  process.exit(0);
}

const ca = await SimulatorCa.loadOrCreate(
  values.ca!,
  values["ca-key"]!,
);

const sim = await FdmsSimulator.create({
  port: Number(values.port),
  host: values.host,
  activationKeys: values["activation-key"],
  closeDelayMs: Number(values["close-delay"]),
  initialFiscalDayNo: Number(values["initial-fiscal-day"]),
  initialGlobalNo: Number(values["initial-global-no"]),
  initialReceiptCounter: Number(values["initial-receipt-counter"]),
  initialPreviousReceiptHash: values["initial-previous-receipt-hash"],
  hosts: values.san,
}, ca);
const { url } = await sim.start();
console.log(`FDMS simulator listening at ${url}`);
console.log(`CA certificate stored at ${values.ca}`);
console.log(`CA private key stored at ${values["ca-key"]}`);
console.log(`Register with any 8-character activation key${values["activation-key"] ? ` from: ${values["activation-key"].join(", ")}` : ""}.`);
console.log(`Replays: RCPT010 RCPT011 RCPT012 RCPT013 RCPT014 RCPT020 RCPT021 RCPT030 RCPT031, async CloseDay, BadCertificateSignature, ReceiptsWithValidationErrors.`);

const stop = () => void sim.stop().then(() => process.exit(0));
process.on("SIGINT", stop);
process.on("SIGTERM", stop);
