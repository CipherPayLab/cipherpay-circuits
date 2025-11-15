#!/usr/bin/env node
/* eslint-disable no-console */
"use strict";

const fs = require("fs");
const fsp = require("fs/promises");
const path = require("path");

const CIRCUITS = ["deposit", "transfer", "withdraw"];

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


const RELAYER_E2E_DIR =
  process.env.RELAYER_E2E_DIR || path.join(RELAYER_ROOT_DEFAULT, "tests/e2e");
const SDK_CIRCUITS_DIR =
  process.env.SDK_CIRCUITS_DIR || path.join(SDK_ROOT_DEFAULT, "src/circuits");

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
  console.log("");

  mustExist(CIRCUITS_BUILD_DIR);

  for (const name of CIRCUITS) {
    const srcDir = path.join(CIRCUITS_BUILD_DIR, name);
    const wasmDir = path.join(srcDir, `${name}_js`);
    const dstDirRelayer = path.join(RELAYER_E2E_DIR, name, "proof");
    const dstDirSdk = path.join(SDK_CIRCUITS_DIR, name);
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

    console.log(`➜ ${name}: done -> ${dstDirRelayer}\n`);
    console.log(`➜ ${name}: done -> ${dstDirSdk}\n`);
  }

  console.log("All artifacts copied successfully ✅");
}

main().catch((err) => {
  console.error("✖ Failed to copy artifacts:", err?.stack || err);
  process.exit(1);
});
