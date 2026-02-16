#!/usr/bin/env node
/* eslint-disable no-console */
"use strict";

const fs = require("fs");
const fsp = require("fs/promises");
const path = require("path");

const CIRCUITS = ["deposit", "transfer", "withdraw", "audit_payment", "audit_withdraw"];

// Paths (defaults assume sibling repos):
//   /home/sean/cipherpay-circuits
//   /home/sean/cipherpay-relayer-solana
const SCRIPT_DIR = __dirname;
const CIRCUITS_ROOT = path.resolve(SCRIPT_DIR, "..");

const CIRCUITS_BUILD_DIR =
  process.env.CIRCUITS_BUILD_DIR || path.join(CIRCUITS_ROOT, "build");

const RELAYER_ROOT_DEFAULT =
  process.env.RELAYER_ROOT || path.resolve(CIRCUITS_ROOT, "../cipherpay-relayer-solana");
const SDK_ROOT_DEFAULT =
  process.env.SDK_ROOT || path.resolve(CIRCUITS_ROOT, "../cipherpay-sdk");
const UI_ROOT_DEFAULT =
  process.env.UI_ROOT || path.resolve(CIRCUITS_ROOT, "../cipherpay-ui");
const ZKAUDIT_ROOT_DEFAULT =
  process.env.ZKAUDIT_ROOT || path.resolve(CIRCUITS_ROOT, "../cipherpay-zkaudit");

const RELAYER_E2E_DIR =
  process.env.RELAYER_E2E_DIR || path.join(RELAYER_ROOT_DEFAULT, "tests/e2e");
const SDK_CIRCUITS_DIR =
  process.env.SDK_CIRCUITS_DIR || path.join(SDK_ROOT_DEFAULT, "src/circuits");
const UI_CIRCUITS_DIR =
  process.env.UI_CIRCUITS_DIR || path.join(UI_ROOT_DEFAULT, "public/circuits");
const ZKAUDIT_UI_CIRCUITS_DIR =
  process.env.ZKAUDIT_CIRCUITS_DIR || path.join(ZKAUDIT_ROOT_DEFAULT, "packages/zkaudit-ui/public/circuits");
const ZKAUDIT_SERVER_CIRCUITS_DIR =
  process.env.ZKAUDIT_SERVER_CIRCUITS_DIR || path.join(ZKAUDIT_ROOT_DEFAULT, "packages/zkaudit-server/assets/vk");
async function ensureDir(p) {
  await fsp.mkdir(p, { recursive: true });
}

async function copyFile(src, dst) {
  await ensureDir(path.dirname(dst));
  await fsp.copyFile(src, dst);
  console.log(`✔ Copied ${src} -> ${dst}`);
}

function mustExist(p) {
  if (!fs.existsSync(p)) {
    console.error(`✖ Not found: ${p}`);
    process.exit(1);
  }
}

async function main() {
  console.log("Copying circuit proof artifacts...");
  console.log(`Source build: ${CIRCUITS_BUILD_DIR}`);
  console.log(`Destination Relayer: ${RELAYER_E2E_DIR}`);
  console.log(`Destination SDK: ${SDK_CIRCUITS_DIR}`);
  console.log(`Destination UI: ${UI_CIRCUITS_DIR}`);
  console.log("");

  mustExist(CIRCUITS_BUILD_DIR);

  for (const name of CIRCUITS) {
    const srcDir = path.join(CIRCUITS_BUILD_DIR, name);
    const wasmDir = path.join(srcDir, `${name}_js`);
    const dstDirRelayer = path.join(RELAYER_E2E_DIR, name, "proof");
    const dstDirSdk = path.join(SDK_CIRCUITS_DIR, name);
    const dstDirUi = path.join(UI_CIRCUITS_DIR, name);
    const dstDirZkauditUi = path.join(ZKAUDIT_UI_CIRCUITS_DIR, name);
    const dstDirZkauditServer = path.join(ZKAUDIT_SERVER_CIRCUITS_DIR, name);

    // sources
    const wasmSrc = path.join(wasmDir, `${name}.wasm`);
    const zkeySrc = path.join(srcDir, `${name}_final.zkey`);
    const vkeySrc = path.join(srcDir, "verification_key.json");

    // destinations (note: vkey renamed to <circuit>_vkey.json)
    const wasmDstRelayer = path.join(dstDirRelayer, `${name}.wasm`);
    const zkeyDstRelayer = path.join(dstDirRelayer, `${name}_final.zkey`);
    const vkeyDstRelayer = path.join(dstDirRelayer, `${name}_vkey.json`);
    const wasmDstSdk = path.join(dstDirSdk, `${name}.wasm`);
    const zkeyDstSdk = path.join(dstDirSdk, `${name}_final.zkey`);
    const vkeyDstSdk = path.join(dstDirSdk, `${name}_vkey.json`);
    const wasmDstUi = path.join(dstDirUi, `${name}.wasm`);
    const zkeyDstUi = path.join(dstDirUi, `${name}_final.zkey`);
    const vkeyDstUi = path.join(dstDirUi, `${name}_vkey.json`);
    const wasmDstZkauditUi = path.join(dstDirZkauditUi, `${name}.wasm`);
    const zkeyDstZkauditUi = path.join(dstDirZkauditUi, `${name}_final.zkey`);
    const vkeyDstZkauditUi = path.join(dstDirZkauditUi, `${name}_vkey.json`);
    const vkeyDstZkauditServer = path.join(dstDirZkauditServer, `${name}_v1.vk.json`);

    // sanity
    for (const p of [srcDir, wasmDir, wasmSrc, zkeySrc, vkeySrc]) {
      mustExist(p);
    }

    await copyFile(wasmSrc, wasmDstRelayer);
    await copyFile(wasmSrc, wasmDstSdk);
    await copyFile(zkeySrc, zkeyDstRelayer);
    await copyFile(zkeySrc, zkeyDstSdk);
    await copyFile(vkeySrc, vkeyDstRelayer);
    await copyFile(vkeySrc, vkeyDstSdk);
    await copyFile(wasmSrc, wasmDstUi);
    await copyFile(zkeySrc, zkeyDstUi);
    await copyFile(vkeySrc, vkeyDstUi);
    await copyFile(wasmSrc, wasmDstZkauditUi);
    await copyFile(zkeySrc, zkeyDstZkauditUi);
    await copyFile(vkeySrc, vkeyDstZkauditUi);
    await copyFile(vkeySrc, vkeyDstZkauditServer);

    console.log(`➜ ${name}: done -> ${dstDirRelayer}\n`);
    console.log(`➜ ${name}: done -> ${dstDirSdk}\n`);
    console.log(`➜ ${name}: done -> ${dstDirUi}\n`);
    console.log(`➜ ${name}: done -> ${dstDirZkauditUi}\n`);
    console.log(`➜ ${name}: done -> ${dstDirZkauditServer}\n`);
  }

  console.log("All artifacts copied successfully ✅");
}

main().catch((err) => {
  console.error("✖ Failed to copy artifacts:", err?.stack || err);
  process.exit(1);
});
