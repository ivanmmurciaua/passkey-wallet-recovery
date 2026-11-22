import {
  concat, createPublicClient, encodeFunctionData, http, keccak256, pad, parseAbi, parseAbiItem, toHex, type Hex,
} from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import {
  CHAIN, NETWORK, PACKED_VERIFIERS, RECOVERY_MODULE_ADDRESS, RPC_URL, SHARED_SIGNER_ADDRESS, WEBAUTHN_VERIFIER_ADDRESS,
} from "@/app/constants";
import { SignerConfig } from "@/types";

export const publicClient = createPublicClient({ chain: CHAIN, transport: http(RPC_URL) });
// Log queries go to an RPC with full history (the default public RPC prunes old logs).
const logsClient = createPublicClient({ chain: CHAIN, transport: http(NETWORK.logsRpcUrl) });

/** RecoveryAuthorityModule (contracts/RecoveryAuthorityModule.sol). */
const moduleAbi = parseAbi([
  "function setupRecovery(bytes signer, uint64 delay)",
  "function disableRecovery()",
  "function request(address safe, uint256 x, uint256 y, uint176 verifiers, bytes signature)",
  "function cancel()",
  "function execute(address safe)",
  "function rotateDigest(address safe, uint256 x, uint256 y, uint176 verifiers) view returns (bytes32)",
  "function recoverySigner(address safe) view returns (bytes)",
  "function recoveryDelay(address safe) view returns (uint64)",
  "function nonces(address safe) view returns (uint256)",
  "function pendingRotation(address safe) view returns (uint256 x, uint256 y, uint176 verifiers, uint64 executeAfter)",
]);
const recoverySetupEvent = parseAbiItem(
  "event RecoverySetup(address indexed safe, bytes32 indexed signerHash, bytes signer, uint64 delay)",
);

const sharedSignerAbi = parseAbi([
  "function getConfiguration(address account) view returns (uint256 x, uint256 y, uint176 verifiers)",
]);
const safeAbi = parseAbi(["function isModuleEnabled(address module) view returns (bool)"]);

// ── ERC-7913 signers ────────────────────────────────────────────────────────────────────

/** Recovery authority = an address (EOA via ecrecover): the 20-byte signer. */
export function signerForAddress(address: string): Hex {
  return address.toLowerCase() as Hex;
}

/** Recovery authority = a passkey: `verifier || qx || qy` (OpenZeppelin ERC7913WebAuthnVerifier). */
export function signerForPasskey(qx: string, qy: string): Hex {
  if (!WEBAUTHN_VERIFIER_ADDRESS) throw new Error("No WebAuthn verifier configured for this network");
  return concat([WEBAUTHN_VERIFIER_ADDRESS, pad(qx as Hex, { size: 32 }), pad(qy as Hex, { size: 32 })]);
}

/** What kind of authority an on-chain signer is, and its key. */
export function describeSigner(signer: Hex): { kind: "address"; address: Hex } | { kind: "passkey"; qx: Hex; qy: Hex } | { kind: "other" } {
  const bytes = (signer.length - 2) / 2;
  if (bytes === 20) return { kind: "address", address: signer };
  if (bytes === 84 && WEBAUTHN_VERIFIER_ADDRESS && signer.slice(0, 42).toLowerCase() === WEBAUTHN_VERIFIER_ADDRESS.toLowerCase()) {
    return { kind: "passkey", qx: `0x${signer.slice(42, 106)}`, qy: `0x${signer.slice(106, 170)}` };
  }
  return { kind: "other" };
}

// ── Reads ───────────────────────────────────────────────────────────────────────────────

export async function isModuleEnabled(safeAddress: string): Promise<boolean> {
  return publicClient.readContract({ address: safeAddress as Hex, abi: safeAbi, functionName: "isModuleEnabled", args: [RECOVERY_MODULE_ADDRESS] });
}

export async function getRecovery(safeAddress: string): Promise<{ signer: Hex; delay: bigint }> {
  const [signer, delay] = await Promise.all([
    publicClient.readContract({ address: RECOVERY_MODULE_ADDRESS, abi: moduleAbi, functionName: "recoverySigner", args: [safeAddress as Hex] }),
    publicClient.readContract({ address: RECOVERY_MODULE_ADDRESS, abi: moduleAbi, functionName: "recoveryDelay", args: [safeAddress as Hex] }),
  ]);
  return { signer, delay };
}

export async function getPending(safeAddress: string): Promise<{ x: bigint; y: bigint; verifiers: bigint; executeAfter: bigint } | null> {
  const [x, y, verifiers, executeAfter] = await publicClient.readContract({
    address: RECOVERY_MODULE_ADDRESS, abi: moduleAbi, functionName: "pendingRotation", args: [safeAddress as Hex],
  });
  return executeAfter === 0n ? null : { x, y, verifiers, executeAfter };
}

export async function getNonce(safeAddress: string): Promise<bigint> {
  return publicClient.readContract({ address: RECOVERY_MODULE_ADDRESS, abi: moduleAbi, functionName: "nonces", args: [safeAddress as Hex] });
}

/** EIP-712 digest the authority signs for the next rotation (it includes the current nonce). */
export async function getRotateDigest(safeAddress: string, x: bigint, y: bigint, verifiers: bigint): Promise<Hex> {
  return publicClient.readContract({
    address: RECOVERY_MODULE_ADDRESS, abi: moduleAbi, functionName: "rotateDigest", args: [safeAddress as Hex, x, y, verifiers],
  });
}

export async function getSharedSignerConfig(safeAddress: string): Promise<SignerConfig> {
  const [x, y, verifiers] = await publicClient.readContract({
    address: SHARED_SIGNER_ADDRESS, abi: sharedSignerAbi, functionName: "getConfiguration", args: [safeAddress as Hex],
  });
  return { x, y, verifiers };
}

/** Latest block timestamp, to compare with `executeAfter`. */
export async function chainTime(): Promise<bigint> {
  return (await publicClient.getBlock()).timestamp;
}

/**
 * Find the Safes whose CURRENT recovery signer is `signer`, from the module's RecoverySetup events
 * (indexed by keccak256(signer)), so a user holding only the recovery key can find the Safe.
 */
export async function findSafesBySigner(signer: Hex): Promise<string[]> {
  const logs = await logsClient.getLogs({
    address: RECOVERY_MODULE_ADDRESS,
    event: recoverySetupEvent,
    args: { signerHash: keccak256(signer) },
    fromBlock: NETWORK.recoveryModuleFromBlock ?? 0n,
    toBlock: "latest",
  });
  const candidates = [...new Set(logs.map((l) => l.args.safe).filter((a): a is Hex => !!a))];
  const current: string[] = [];
  for (const safe of candidates) {
    if ((await getRecovery(safe)).signer.toLowerCase() === signer.toLowerCase()) current.push(safe);
  }
  return current;
}

// ── Calldata ────────────────────────────────────────────────────────────────────────────

export function encodeEnableModule(moduleAddress: string): Hex {
  return encodeFunctionData({
    abi: parseAbi(["function enableModule(address module)"]),
    functionName: "enableModule",
    args: [moduleAddress as Hex],
  });
}

export const encodeSetupRecovery = (signer: Hex, delay: bigint): Hex =>
  encodeFunctionData({ abi: moduleAbi, functionName: "setupRecovery", args: [signer, delay] });

export const encodeRequest = (safe: string, x: bigint, y: bigint, verifiers: bigint, signature: Hex): Hex =>
  encodeFunctionData({ abi: moduleAbi, functionName: "request", args: [safe as Hex, x, y, verifiers, signature] });

export const encodeCancel = (): Hex => encodeFunctionData({ abi: moduleAbi, functionName: "cancel" });

export const encodeExecute = (safe: string): Hex =>
  encodeFunctionData({ abi: moduleAbi, functionName: "execute", args: [safe as Hex] });

// ── Signing with an address authority ───────────────────────────────────────────────────

export function generateRecoveryKey(): { privateKey: Hex; address: string } {
  const privateKey = generatePrivateKey();
  return { privateKey, address: privateKeyToAccount(privateKey).address };
}

/** Raw ECDSA over the EIP-712 digest (no prefix), as `ecrecover` in the module expects. */
export async function signDigestWithKey(privateKey: Hex, digest: Hex): Promise<Hex> {
  return privateKeyToAccount(privateKey).sign({ hash: digest });
}

export function defaultVerifiers(): bigint {
  return PACKED_VERIFIERS;
}

export { toHex };
