import { createPublicClient, http, encodeFunctionData, parseAbi } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { CHAIN, CHAIN_ID, PACKED_VERIFIERS, RECOVERY_MODULE_ADDRESS, RPC_URL, SHARED_SIGNER_ADDRESS } from "@/app/constants";
import { SignerConfig } from "@/types";

export const publicClient = createPublicClient({ chain: CHAIN, transport: http(RPC_URL) });

const recoveryModuleAbi = parseAbi([
  "function setupRecovery(address recoveryKey) external",
  "function recover(address safe, uint256 newX, uint256 newY, uint176 verifiers, bytes calldata signature) external",
  "function nonces(address safe) external view returns (uint256)",
  "function recoveryKeys(address safe) external view returns (address)",
]);

const sharedSignerAbi = parseAbi([
  "function getConfiguration(address account) external view returns (uint256 x, uint256 y, uint176 verifiers)",
]);

const safeAbi = parseAbi([
  "function isModuleEnabled(address module) external view returns (bool)",
]);

export async function isModuleEnabled(safeAddress: string): Promise<boolean> {
  return (await publicClient.readContract({
    address: safeAddress as `0x${string}`,
    abi: safeAbi,
    functionName: "isModuleEnabled",
    args: [RECOVERY_MODULE_ADDRESS],
  })) as boolean;
}

export function generateRecoveryKey(): { privateKey: `0x${string}`; address: string } {
  const privateKey = generatePrivateKey();
  const account = privateKeyToAccount(privateKey);
  return { privateKey, address: account.address };
}

export function encodeSetupRecovery(recoveryAddress: string): string {
  return encodeFunctionData({
    abi: recoveryModuleAbi,
    functionName: "setupRecovery",
    args: [recoveryAddress as `0x${string}`],
  });
}

export function encodeEnableModule(moduleAddress: string): string {
  return encodeFunctionData({
    abi: parseAbi(["function enableModule(address module) external"]),
    functionName: "enableModule",
    args: [moduleAddress as `0x${string}`],
  });
}

export async function getRecoveryKey(safeAddress: string): Promise<string> {
  return (await publicClient.readContract({
    address: RECOVERY_MODULE_ADDRESS,
    abi: recoveryModuleAbi,
    functionName: "recoveryKeys",
    args: [safeAddress as `0x${string}`],
  })) as string;
}

export async function getSharedSignerConfig(safeAddress: string): Promise<SignerConfig> {
  const result = await publicClient.readContract({
    address: SHARED_SIGNER_ADDRESS,
    abi: sharedSignerAbi,
    functionName: "getConfiguration",
    args: [safeAddress as `0x${string}`],
  });
  // viem returns the tuple as [x, y, verifiers] or as object depending on ABI
  const [x, y, verifiers] = result as [bigint, bigint, bigint];
  return { x, y, verifiers };
}

export async function getRecoveryNonce(safeAddress: string): Promise<bigint> {
  return (await publicClient.readContract({
    address: RECOVERY_MODULE_ADDRESS,
    abi: recoveryModuleAbi,
    functionName: "nonces",
    args: [safeAddress as `0x${string}`],
  })) as bigint;
}

export async function signRecovery(params: {
  privateKey: `0x${string}`;
  safeAddress: string;
  newX: bigint;
  newY: bigint;
  verifiers: bigint;
  nonce: bigint;
}): Promise<`0x${string}`> {
  const account = privateKeyToAccount(params.privateKey);

  return account.signTypedData({
    domain: {
      name: "RecoveryModule",
      version: "1",
      chainId: CHAIN_ID,
      verifyingContract: RECOVERY_MODULE_ADDRESS,
    },
    types: {
      Recover: [
        { name: "safe", type: "address" },
        { name: "x", type: "uint256" },
        { name: "y", type: "uint256" },
        { name: "verifiers", type: "uint176" },
        { name: "nonce", type: "uint256" },
      ],
    },
    primaryType: "Recover",
    message: {
      safe: params.safeAddress as `0x${string}`,
      x: params.newX,
      y: params.newY,
      verifiers: params.verifiers,
      nonce: params.nonce,
    },
  });
}

export function encodeRecover(params: {
  safeAddress: string;
  newX: bigint;
  newY: bigint;
  verifiers: bigint;
  signature: `0x${string}`;
}): string {
  return encodeFunctionData({
    abi: recoveryModuleAbi,
    functionName: "recover",
    args: [
      params.safeAddress as `0x${string}`,
      params.newX,
      params.newY,
      params.verifiers,
      params.signature,
    ],
  });
}

// Returns the packed verifiers value: EIP-7951 precompile (0x0100) + Daimo fallback
// P256.sol tries the precompile first (6.9k gas), falls back to Daimo if empty
export function defaultVerifiers(): bigint {
  return PACKED_VERIFIERS;
}
