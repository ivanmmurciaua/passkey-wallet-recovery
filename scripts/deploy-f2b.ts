// Deploy F2b contracts on the active network (constants.ts): RecoveryAuthorityModule and the
// ERC-7913 WebAuthn verifier. Requires DEPLOYER_PRIVATE_KEY (funded) in .env.local.
// Usage: npx hardhat compile && npx tsx scripts/deploy-f2b.ts
import { readFileSync } from "fs";
import { config as dotenv } from "dotenv";
import { createPublicClient, createWalletClient, http, type Abi, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { CANONICAL, NETWORK } from "../src/app/constants";

dotenv({ path: ".env.local" });

/** Lower bound for the per-Safe delay. Short on purpose: this is a testnet PoC. */
const MIN_DELAY = 60n;

function artifact(path: string): { abi: Abi; bytecode: Hex } {
  return JSON.parse(readFileSync(path, "utf8"));
}

async function main() {
  const pk = process.env.DEPLOYER_PRIVATE_KEY as Hex | undefined;
  if (!pk) throw new Error("DEPLOYER_PRIVATE_KEY not set in .env.local");
  const account = privateKeyToAccount(pk);
  const wallet = createWalletClient({ account, chain: NETWORK.chain, transport: http(NETWORK.rpcUrl) });
  const client = createPublicClient({ chain: NETWORK.chain, transport: http(NETWORK.rpcUrl) });
  console.log(`Deploying on ${NETWORK.key} (chain ${NETWORK.chain.id}) from ${account.address}`);

  const mod = artifact("artifacts/contracts/RecoveryAuthorityModule.sol/RecoveryAuthorityModule.json");
  const h1 = await wallet.deployContract({ abi: mod.abi, bytecode: mod.bytecode, args: [CANONICAL.webAuthnSharedSigner, MIN_DELAY] });
  const r1 = await client.waitForTransactionReceipt({ hash: h1 });
  console.log(`RecoveryAuthorityModule: ${r1.contractAddress} (block ${r1.blockNumber}, tx ${h1})`);

  const ver = artifact("artifacts/contracts/verifiers/WebAuthnVerifier.sol/WebAuthnVerifier.json");
  const h2 = await wallet.deployContract({ abi: ver.abi, bytecode: ver.bytecode });
  const r2 = await client.waitForTransactionReceipt({ hash: h2 });
  console.log(`WebAuthnVerifier (ERC-7913): ${r2.contractAddress} (block ${r2.blockNumber}, tx ${h2})`);

  console.log("\nAdd both to NETWORKS in src/app/constants.ts (recoveryAuthorityModule, its from-block, webAuthnVerifier).");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
