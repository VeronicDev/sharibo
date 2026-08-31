const fs = require("fs");
const path = require("path");
const { expect } = require("chai");
const wasm_tester = require("circom_tester").wasm;
const {
  generateIdentity,
  computeExternalNullifier,
  computeNullifierHash,
  poseidon,
  FR_MODULUS,
} = require("../../packages/client/src/identity.ts");
const { MerkleTree } = require("../../packages/client/src/tree.ts");

// Single source of truth for the tree depth is circuits/config.json (see
// "Changing the Merkle tree depth" in the repo README) — read it here
// instead of hardcoding the level count a second time.
const { generate: generateCircuit } = require("../scripts/gen-circuit.cjs");
const CIRCUITS_CONFIG = JSON.parse(
  fs.readFileSync(path.join(__dirname, "..", "config.json"), "utf8"),
);
const LEVELS = CIRCUITS_CONFIG.levels;

const VECTORS = JSON.parse(
  fs.readFileSync(path.join(__dirname, "..", "..", "test-vectors", "poseidon.json"), "utf8"),
);

describe("Sharibo membership circuit (BLS12-381)", function () {
  this.timeout(120000);

  let circuit;
  let identities;
  let tree;

  before(async () => {
    // Regenerate membership.circom from the template + config.json so the
    // test always exercises the circuit matching the current tree depth.
    generateCircuit();

    circuit = await wasm_tester(path.join(__dirname, "..", "membership.circom"), {
      include: path.join(__dirname, "..", "..", "node_modules"),
      prime: "bls12381",
    });

    identities = Array.from({ length: 5 }, () => generateIdentity());
    tree = MerkleTree.create(
      LEVELS,
      identities.map((id) => id.commitment),
    );
  });

  // Deterministic recipientHash for testing: Poseidon(payout_nullifier, payout_secret)
  const TEST_RECIPIENT_HASH = poseidon(111n, 222n);

  async function buildInput(memberIndex, circleId, round) {
    const identity = identities[memberIndex];
    const merkleProof = tree.proof(memberIndex);
    const externalNullifier = await computeExternalNullifier(BigInt(circleId), BigInt(round));
    return {
      identityNullifier: identity.identityNullifier.toString(),
      identitySecret: identity.identitySecret.toString(),
      pathElements: merkleProof.pathElements.map((e) => e.toString()),
      pathIndices: merkleProof.pathIndices,
      root: merkleProof.root.toString(),
      externalNullifier: externalNullifier.toString(),
      recipientHash: TEST_RECIPIENT_HASH.toString(),
    };
  }

  async function expectThrows(fn) {
    let threw = false;
    try {
      await fn();
    } catch (e) {
      threw = true;
    }
    expect(threw, "expected the operation to throw").to.equal(true);
  }

  it("accepts a genuine member and outputs the correct nullifierHash", async () => {
    const input = await buildInput(2, 1, 0);
    const witness = await circuit.calculateWitness(input, true);
    await circuit.checkConstraints(witness);

    const expected = computeNullifierHash(
      identities[2].identityNullifier,
      BigInt(input.externalNullifier),
    );
    await circuit.assertOut(witness, { nullifierHash: expected.toString() });
  });

  it("rejects a wrong root", async () => {
    const input = await buildInput(2, 1, 0);
    input.root = (BigInt(input.root) + 1n).toString();
    await expectThrows(() => circuit.calculateWitness(input, true));
  });

  it("rejects a non-member (tampered Merkle path)", async () => {
    const input = await buildInput(2, 1, 0);
    input.pathElements[0] = (BigInt(input.pathElements[0]) + 1n).toString();
    await expectThrows(() => circuit.calculateWitness(input, true));
  });

  it("nullifierHash is deterministic per identity+round and changes across rounds", async () => {
    await circuit.loadSymbols();
    const varIdx = circuit.symbols["main.nullifierHash"].varIdx;

    const inputA = await buildInput(3, 7, 0);
    const inputB = await buildInput(3, 7, 0);
    const inputNextRound = await buildInput(3, 7, 1);

    const witnessA = await circuit.calculateWitness(inputA, true);
    const witnessB = await circuit.calculateWitness(inputB, true);
    const witnessNextRound = await circuit.calculateWitness(inputNextRound, true);

    expect(witnessA[varIdx].toString()).to.equal(witnessB[varIdx].toString());
    expect(witnessA[varIdx].toString()).to.not.equal(witnessNextRound[varIdx].toString());
  });

  it("rejects a non-boolean pathIndices entry", async () => {
    const input = await buildInput(2, 1, 0);
    input.pathIndices[0] = 2;
    await expectThrows(() => circuit.calculateWitness(input, true));
  });

  // --- recipientHash binding tests (issue #266) ---

  it("accepts a genuine member with a valid recipientHash", async () => {
    const input = await buildInput(2, 1, 0);
    const witness = await circuit.calculateWitness(input, true);
    await circuit.checkConstraints(witness);

    const expected = computeNullifierHash(
      identities[2].identityNullifier,
      BigInt(input.externalNullifier),
    );
    await circuit.assertOut(witness, { nullifierHash: expected.toString() });
  });

  it("rejects a proof when recipientHash is swapped to a different value", async () => {
    const input = await buildInput(2, 1, 0);
    // Swap to a different recipientHash
    const differentRecipientHash = poseidon(333n, 444n);
    input.recipientHash = differentRecipientHash.toString();
    await expectThrows(() => circuit.calculateWitness(input, true));
  });

  it("public signals are pinned: [nullifierHash, root, externalNullifier, recipientHash]", async () => {
    const input = await buildInput(1, 4, 2);
    const witness = await circuit.calculateWitness(input, true);
    await circuit.checkConstraints(witness);

    // witness[0] is always the constant wire (1); the next four slots are
    // the public signals in the exact order snarkjs would emit them.
    const publicSignals = [
      witness[1].toString(),
      witness[2].toString(),
      witness[3].toString(),
      witness[4].toString(),
    ];

    const expectedNullifierHash = computeNullifierHash(
      identities[1].identityNullifier,
      BigInt(input.externalNullifier),
    );

    expect(publicSignals[0]).to.equal(expectedNullifierHash.toString());
    expect(publicSignals[1]).to.equal(input.root);
    expect(publicSignals[2]).to.equal(input.externalNullifier);
    expect(publicSignals[3]).to.equal(input.recipientHash);
  });

  // Cross-implementation fixture shared with
  // packages/client/src/poseidon-vectors.test.ts (see
  // test-vectors/generate.mjs). If only ONE side fails after a dependency
  // bump, the client and circuit Poseidon implementations have diverged -
  // do NOT edit the vectors to match, fix the divergence instead.
  it("reproduces the committed cross-implementation test vector (issue #67)", async () => {
    const { input, expectedPublicSignals } = VECTORS.fullCircuitExample;
    const witness = await circuit.calculateWitness(input, true);
    await circuit.checkConstraints(witness);
    await circuit.assertOut(witness, { nullifierHash: expectedPublicSignals.nullifierHash });
  });

  // Public signal order is the trickiest invariant in the repo: snarkjs
  // emits [nullifierHash, root, externalNullifier] - circuit output first,
  // then the public inputs in the order they're declared in the template
  // (see prove.ts). This pins both the VALUE and the POSITION: swapping the
  // `signal input root` / `signal input externalNullifier` declarations in
  // membership.circom would make this test fail (issue #69).
  it("public signals are pinned by position: [nullifierHash, root, externalNullifier]", async () => {
    const input = await buildInput(1, 4, 2);
    const witness = await circuit.calculateWitness(input, true);
    await circuit.checkConstraints(witness);

    // witness[0] is always the constant wire (1); the next three slots are
    // the public signals in the exact order snarkjs would emit them.
    const publicSignals = [witness[1].toString(), witness[2].toString(), witness[3].toString()];

    const expectedNullifierHash = computeNullifierHash(
      identities[1].identityNullifier,
      BigInt(input.externalNullifier),
    );

    expect(publicSignals[0]).to.equal(expectedNullifierHash.toString());
    expect(publicSignals[1]).to.equal(input.root);
    expect(publicSignals[2]).to.equal(input.externalNullifier);
  });

  // externalNullifier boundary values (issue #70). In practice it's always
  // `SHA256(...) mod r` (< r), but the circuit takes it as a raw,
  // unconstrained public input - nothing in the circuit itself enforces a
  // range on it.
  it("accepts externalNullifier = 0 (valid extreme)", async () => {
    const input = await buildInput(0, 11, 0);
    input.externalNullifier = "0";
    const witness = await circuit.calculateWitness(input, true);
    await circuit.checkConstraints(witness);
    const expected = computeNullifierHash(identities[0].identityNullifier, 0n);
    await circuit.assertOut(witness, { nullifierHash: expected.toString() });
  });

  it("accepts externalNullifier = r - 1 (valid extreme)", async () => {
    const input = await buildInput(0, 11, 0);
    const maxExternalNullifier = FR_MODULUS - 1n;
    input.externalNullifier = maxExternalNullifier.toString();
    const witness = await circuit.calculateWitness(input, true);
    await circuit.checkConstraints(witness);
    const expected = computeNullifierHash(identities[0].identityNullifier, maxExternalNullifier);
    await circuit.assertOut(witness, { nullifierHash: expected.toString() });
  });

  it("documents that externalNullifier binding is enforced by the verifier, not the circuit", async () => {
    // The circuit happily computes a witness for ANY externalNullifier
    // value (0 and r-1 above both satisfy all constraints) - it does not
    // itself bind the proof to one specific externalNullifier. What
    // actually prevents a prover from claiming a different
    // externalNullifier than the one they proved against is the verifier
    // comparing the proof's public signals (which include
    // externalNullifier verbatim, and nullifierHash which is a function of
    // it) to the externalNullifier value the verifier independently
    // expects for this round. A mismatched externalNullifier yields a
    // different, non-matching nullifierHash:
    const input = await buildInput(0, 13, 0);
    const witness = await circuit.calculateWitness(input, true);
    await circuit.checkConstraints(witness);

    const mismatchedExternalNullifier = (BigInt(input.externalNullifier) + 1n) % FR_MODULUS;
    const actualNullifierHash = computeNullifierHash(
      identities[0].identityNullifier,
      BigInt(input.externalNullifier),
    );
    const nullifierHashForMismatch = computeNullifierHash(
      identities[0].identityNullifier,
      mismatchedExternalNullifier,
    );

    expect(actualNullifierHash.toString()).to.not.equal(nullifierHashForMismatch.toString());
    await circuit.assertOut(witness, { nullifierHash: actualNullifierHash.toString() });
  });
});
