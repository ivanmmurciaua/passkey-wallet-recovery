// Single source of truth for every version, address and network this PoC uses.
// Nothing else in the repo (lib, page, scripts, hardhat config) may hardcode an address,
// a version or an RPC URL: import it from here. `npm run check:constants` compares this
// file with the official Safe deployment registries and fails loudly on any mismatch.
import { Address, Chain, toHex } from "viem";
import { sepolia } from "viem/chains";

// ── Versions ────────────────────────────────────────────────────────────────────────────

export const VERSIONS = {
  /** Safe singleton (SafeL2) + proxy factory + fallback handler. 1.5.0 adds the module guard
   *  (IModuleGuard.checkModuleTransaction), which sees UserOps executed by Safe4337Module. */
  safe: "1.5.0",
  /** Safe4337Module + SafeModuleSetup (safe-modules-deployments "safe-4337-module"). */
  safe4337Module: "0.3.0",
  /** SafeWebAuthnSharedSigner + SignerFactory + Daimo verifier ("safe-passkey-module"). */
  safePasskeyModule: "0.2.1",
  /** ERC-4337 EntryPoint required by Safe4337Module v0.3.0. */
  entryPoint: "0.7",
} as const;

// ── Canonical addresses (identical on every supported network) ────────────────────────

export const CANONICAL = {
  entryPoint: "0x0000000071727De22E5E9d8BAf0edAc6f37da032" as Address,
  safe4337Module: "0x75cf11467937ce3F2f357CE24ffc3DBF8fD5c226" as Address,
  safeModuleSetup: "0x2dd68b007B46fBe91B9A7c3EDa5A7a1063cB5b47" as Address,
  /** Owner of every passkey Safe; stores (x, y, verifiers) in the Safe's own storage.
   *  contracts/RecoveryModule.sol mirrors this address (same on every network). */
  webAuthnSharedSigner: "0x94a4F6affBd8975951142c3999aEAB7ecee555c2" as Address,
  webAuthnSignerFactory: "0x1d31F259eE307358a26dFb23EB365939E8641195" as Address,
  /** Solidity P-256 verifier, the fallback when the precompile is absent. */
  daimoP256Verifier: "0xc2b78104907F722DABAc4C69f826a522B2754De4" as Address,
} as const;

/** P256VERIFY precompile: EIP-7951 on L1 (since Fusaka), RIP-7212 on L2s. */
export const P256_PRECOMPILE = 0x0100n;

/**
 * Packed verifiers stored per passkey: upper 16 bits = precompile, lower 160 bits = fallback.
 * P256.sol tries the precompile first (~6.9k gas) and falls back to Daimo if it returns empty.
 * protocol-kit 8 takes this uint176 as the passkey's `verifierAddress` and uses it as-is.
 */
export const PACKED_VERIFIERS = (P256_PRECOMPILE << 160n) | BigInt(CANONICAL.daimoP256Verifier);
export const PACKED_VERIFIERS_HEX = toHex(PACKED_VERIFIERS);

// ── Networks ────────────────────────────────────────────────────────────────────────────

// The PoC targets Ethereum Sepolia only. Add a network here (and run check:constants) to extend it.
export type NetworkKey = "sepolia";

export interface NetworkConfig {
  key: NetworkKey;
  chain: Chain;
  rpcUrl: string;
  /** RPC with full log history for eth_getLogs (many public RPCs prune old logs or cap ranges). */
  logsRpcUrl: string;
  /** Slug used in Pimlico's v2 URLs. */
  pimlicoSlug: string;
  explorerUrl: string;
  /** Which P-256 precompile spec the network implements (gas differs). */
  p256Precompile: "EIP-7951" | "RIP-7212";
  /** Our RecoveryModule on this network, if deployed, and the block to start log searches from. */
  recoveryModule?: Address;
  recoveryModuleFromBlock?: bigint;
}

export const NETWORKS: Record<NetworkKey, NetworkConfig> = {
  sepolia: {
    key: "sepolia",
    chain: sepolia,
    rpcUrl: "https://ethereum-sepolia-rpc.publicnode.com",
    logsRpcUrl: "https://sepolia.gateway.tenderly.co",
    pimlicoSlug: "sepolia",
    explorerUrl: "https://sepolia.etherscan.io",
    p256Precompile: "EIP-7951",
    recoveryModule: "0x0cc7d46dd3247aa14099bf4baf16d1798d7a12d3",
    recoveryModuleFromBlock: 10_863_000n, // first RecoverySetup event at 10,863,681
  },
};

/** Active network: NEXT_PUBLIC_NETWORK (only "sepolia" today), default sepolia. */
export const NETWORK: NetworkConfig =
  NETWORKS[(process.env.NEXT_PUBLIC_NETWORK as NetworkKey) ?? "sepolia"] ?? NETWORKS.sepolia;

// ── Derived values for the active network (what the app imports) ───────────────────────

export const CHAIN = NETWORK.chain;
export const CHAIN_ID = NETWORK.chain.id;
export const RPC_URL = NETWORK.rpcUrl;

const pimlico = (slug: string) =>
  `https://api.pimlico.io/v2/${slug}/rpc?apikey=${process.env.NEXT_PUBLIC_PIMLICO_API_KEY}`;
export const BUNDLER_URL = pimlico(NETWORK.pimlicoSlug);
export const PAYMASTER_URL = pimlico(NETWORK.pimlicoSlug);

export const ENTRYPOINT_ADDRESS = CANONICAL.entryPoint;
export const SAFE_MODULES_VERSION = VERSIONS.safe4337Module;
export const SAFE_MODULES_ADDRESS = CANONICAL.safe4337Module;
export const SAFE_SW_VERSION = VERSIONS.safe;
export const SHARED_SIGNER_ADDRESS = CANONICAL.webAuthnSharedSigner;
export const DAIMO_VERIFIER_ADDRESS = CANONICAL.daimoP256Verifier;

/** RecoveryModule on the active network: env override, else the registry above. */
export const RECOVERY_MODULE_ADDRESS = (process.env.NEXT_PUBLIC_RECOVERY_MODULE_ADDRESS ||
  NETWORK.recoveryModule ||
  "") as Address;
