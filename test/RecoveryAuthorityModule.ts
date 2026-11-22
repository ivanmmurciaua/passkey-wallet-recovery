import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { network } from "hardhat";
import { concat, encodeAbiParameters, encodeFunctionData, keccak256, sha256, toBytes, toHex, type Hex } from "viem";
import { p256 } from "@noble/curves/nist.js";

const MIN_DELAY = 60n;
const DELAY = 3600n;
const VERIFIERS = (0x0100n << 160n) | 0xc2b78104907f722dabac4c69f826a522b2754de4n;

async function setup() {
  const { viem, networkHelpers } = await network.create();
  const [deployer, recoveryEoa, stranger] = await viem.getWalletClients();
  const publicClient = await viem.getPublicClient();
  const sharedSigner = await viem.deployContract("MockSharedSigner");
  const recovery = await viem.deployContract("RecoveryAuthorityModule", [sharedSigner.address, MIN_DELAY]);
  const safe = await viem.deployContract("MockSafe");
  await safe.write.enableModule([recovery.address]);
  const chainId = await publicClient.getChainId();

  // Call a recovery function AS the Safe (stands in for a UserOp signed by the current passkey).
  const asSafe = (functionName: "setupRecovery" | "disableRecovery" | "cancel", args: readonly unknown[] = []) =>
    safe.write.exec([recovery.address, encodeFunctionData({ abi: recovery.abi, functionName, args } as never)]);

  const signRotate = (signer: typeof recoveryEoa, x: bigint, y: bigint, nonce: bigint, safeAddress: Hex = safe.address) =>
    signer.signTypedData({
      domain: { name: "RecoveryAuthorityModule", version: "1", chainId, verifyingContract: recovery.address },
      types: {
        Rotate: [
          { name: "safe", type: "address" },
          { name: "x", type: "uint256" },
          { name: "y", type: "uint256" },
          { name: "verifiers", type: "uint176" },
          { name: "nonce", type: "uint256" },
        ],
      },
      primaryType: "Rotate",
      message: { safe: safeAddress, x, y, verifiers: VERIFIERS, nonce },
    });

  return { viem, networkHelpers, deployer, recoveryEoa, stranger, recovery, safe, asSafe, signRotate };
}

describe("RecoveryAuthorityModule", () => {
  it("rejects a delay below MIN_DELAY and a signer shorter than 20 bytes", async () => {
    const { recoveryEoa, asSafe } = await setup();
    await assert.rejects(asSafe("setupRecovery", [recoveryEoa.account.address, MIN_DELAY - 1n]), /DelayTooShort/);
    await assert.rejects(asSafe("setupRecovery", ["0x1234", DELAY]), /InvalidSigner/);
  });

  it("EOA authority: request, then execute only after the delay", async () => {
    const { networkHelpers, recoveryEoa, recovery, safe, asSafe, signRotate } = await setup();
    await asSafe("setupRecovery", [recoveryEoa.account.address, DELAY]);
    const sig = await signRotate(recoveryEoa, 11n, 22n, 0n);
    await recovery.write.request([safe.address, 11n, 22n, VERIFIERS, sig]);
    assert.equal(await recovery.read.nonces([safe.address]), 1n);

    await assert.rejects(recovery.write.execute([safe.address]), /TooEarly/);
    await networkHelpers.time.increase(Number(DELAY));
    await recovery.write.execute([safe.address]);

    const [x, y, v] = await safe.read.signerConfig();
    assert.deepEqual([x, y, v], [11n, 22n, VERIFIERS]);
    await assert.rejects(recovery.write.execute([safe.address]), /NoPendingRotation/);
  });

  it("a signature is single-use (nonce bound) and only the authority can sign", async () => {
    const { networkHelpers, recoveryEoa, stranger, recovery, safe, asSafe, signRotate } = await setup();
    await asSafe("setupRecovery", [recoveryEoa.account.address, DELAY]);
    const sig = await signRotate(recoveryEoa, 1n, 2n, 0n);
    await recovery.write.request([safe.address, 1n, 2n, VERIFIERS, sig]);
    await networkHelpers.time.increase(Number(DELAY));
    await recovery.write.execute([safe.address]);
    await assert.rejects(recovery.write.request([safe.address, 1n, 2n, VERIFIERS, sig]), /InvalidAuthoritySignature/);

    const forged = await signRotate(stranger, 3n, 4n, 1n);
    await assert.rejects(recovery.write.request([safe.address, 3n, 4n, VERIFIERS, forged]), /InvalidAuthoritySignature/);
  });

  it("the Safe cancels a pending rotation; nobody else can", async () => {
    const { networkHelpers, recoveryEoa, stranger, recovery, safe, asSafe, signRotate } = await setup();
    await asSafe("setupRecovery", [recoveryEoa.account.address, DELAY]);
    await recovery.write.request([safe.address, 5n, 6n, VERIFIERS, await signRotate(recoveryEoa, 5n, 6n, 0n)]);
    await assert.rejects(recovery.write.cancel({ account: stranger.account }), /NoPendingRotation/);
    await asSafe("cancel");
    await networkHelpers.time.increase(Number(DELAY));
    await assert.rejects(recovery.write.execute([safe.address]), /NoPendingRotation/);
    const [x] = await safe.read.signerConfig();
    assert.equal(x, 0n);
  });

  it("one pending rotation at a time; replacing or disabling the authority drops it", async () => {
    const { recoveryEoa, stranger, recovery, safe, asSafe, signRotate } = await setup();
    await asSafe("setupRecovery", [recoveryEoa.account.address, DELAY]);
    await recovery.write.request([safe.address, 7n, 8n, VERIFIERS, await signRotate(recoveryEoa, 7n, 8n, 0n)]);
    await assert.rejects(
      recovery.write.request([safe.address, 9n, 9n, VERIFIERS, await signRotate(recoveryEoa, 9n, 9n, 1n)]),
      /RotationAlreadyPending/,
    );
    await asSafe("setupRecovery", [stranger.account.address, DELAY]);
    assert.equal((await recovery.read.pendingRotation([safe.address]))[3], 0n);
    await asSafe("disableRecovery");
    await assert.rejects(
      recovery.write.request([safe.address, 1n, 1n, VERIFIERS, await signRotate(stranger, 1n, 1n, 1n)]),
      /RecoveryNotSetUp/,
    );
  });

  it("execute fails if the recovery is not enabled on the Safe", async () => {
    const { viem, networkHelpers, recoveryEoa, recovery, signRotate } = await setup();
    const bare = await viem.deployContract("MockSafe"); // recovery NOT enabled
    await bare.write.exec([
      recovery.address,
      encodeFunctionData({ abi: recovery.abi, functionName: "setupRecovery", args: [recoveryEoa.account.address, DELAY] }),
    ]);
    const sig = await signRotate(recoveryEoa, 1n, 1n, 0n, bare.address);
    await recovery.write.request([bare.address, 1n, 1n, VERIFIERS, sig]);
    await networkHelpers.time.increase(Number(DELAY));
    await assert.rejects(recovery.write.execute([bare.address]), /GS104/);
  });

  it("ERC-7913 WebAuthn authority (verifier || qx || qy) with a real P-256 assertion", async () => {
    const { viem, networkHelpers, recovery, safe, asSafe } = await setup();
    const verifier = await viem.deployContract("WebAuthnVerifier");

    const sk = p256.utils.randomSecretKey();
    const pub = p256.getPublicKey(sk, false);
    const qx = toHex(pub.slice(1, 33));
    const qy = toHex(pub.slice(33, 65));
    const signer = concat([verifier.address, qx, qy]);
    await asSafe("setupRecovery", [signer, DELAY]);

    const digest = await recovery.read.rotateDigest([safe.address, 13n, 14n, VERIFIERS]);
    // WebAuthn assertion over the digest: challenge = base64url(digest).
    const challenge = Buffer.from(toBytes(digest)).toString("base64url");
    const clientDataJSON = JSON.stringify({ type: "webauthn.get", challenge, origin: "http://localhost:3000", crossOrigin: false });
    const authenticatorData = concat([keccak256(toHex("localhost")), "0x05", "0x00000001"]); // rpIdHash || flags(UP|UV) || counter
    const message = sha256(concat([authenticatorData, sha256(toHex(clientDataJSON))]));
    // @noble/curves returns raw bytes or a Signature object depending on the version.
    const signed = p256.sign(toBytes(message), sk, { prehash: false, lowS: true }) as unknown;
    const rs: Uint8Array = signed instanceof Uint8Array
      ? signed
      : (signed as { toBytes?: (f: string) => Uint8Array }).toBytes?.("compact") ??
        (signed as { toCompactRawBytes: () => Uint8Array }).toCompactRawBytes();
    // OpenZeppelin's WebAuthn.tryDecodeAuth reads the struct fields from offset 0 (no outer tuple
    // offset), i.e. abi.encode of the six fields.
    const auth = encodeAbiParameters(
      [
        { name: "r", type: "bytes32" }, { name: "s", type: "bytes32" },
        { name: "challengeIndex", type: "uint256" }, { name: "typeIndex", type: "uint256" },
        { name: "authenticatorData", type: "bytes" }, { name: "clientDataJSON", type: "string" },
      ],
      [
        toHex(rs.slice(0, 32)), toHex(rs.slice(32, 64)),
        BigInt(clientDataJSON.indexOf('"challenge"')), BigInt(clientDataJSON.indexOf('"type"')),
        authenticatorData, clientDataJSON,
      ],
    );

    await recovery.write.request([safe.address, 13n, 14n, VERIFIERS, auth]);
    await networkHelpers.time.increase(Number(DELAY));
    await recovery.write.execute([safe.address]);
    const [x, y] = await safe.read.signerConfig();
    assert.deepEqual([x, y], [13n, 14n]);

    // The same assertion cannot authorize other coordinates (it signs the digest of 13, 14).
    await assert.rejects(recovery.write.request([safe.address, 99n, 99n, VERIFIERS, auth]), /InvalidAuthoritySignature/);
  });
});
