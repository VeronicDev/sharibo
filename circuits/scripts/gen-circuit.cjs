#!/usr/bin/env node
// Regenerates circuits/membership.circom from
// circuits/membership.template.circom + circuits/config.json — the single
// source of truth for the Merkle tree depth (see the "Changing the Merkle
// tree depth" section in the repo README). Run automatically by
// scripts/compile.sh and by the circuit test suite; safe to run manually:
//
//   node scripts/gen-circuit.cjs
"use strict";
const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");

function generate() {
  const config = JSON.parse(fs.readFileSync(path.join(ROOT, "config.json"), "utf8"));
  const template = fs.readFileSync(path.join(ROOT, "membership.template.circom"), "utf8");

  const output =
    template.trimEnd() +
    `\n\ncomponent main { public [root, externalNullifier, recipientHash] } = Sharibo(${config.levels});\n`;

  const outPath = path.join(ROOT, "membership.circom");
  fs.writeFileSync(outPath, output);
  return { outPath, levels: config.levels };
}

if (require.main === module) {
  const { outPath, levels } = generate();
  console.log(`generated ${outPath} for levels=${levels}`);
}

module.exports = { generate };
