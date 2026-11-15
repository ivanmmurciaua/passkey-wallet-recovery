import { createWalletClient, createPublicClient, http } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { NETWORK } from "../src/app/constants";
import { readFileSync } from "fs";

const artifact = JSON.parse(
  readFileSync("artifacts/contracts/RecoveryModule.sol/RecoveryModule.json", "utf8"),
);

async function main() {
  const privateKey = process.env.DEPLOYER_PRIVATE_KEY as `0x${string}`;
  if (!privateKey) throw new Error("DEPLOYER_PRIVATE_KEY not set in .env.local");

  const account = privateKeyToAccount(privateKey);
  console.log(`Deploying on ${NETWORK.key} (chain ${NETWORK.chain.id}) with:`, account.address);

  const walletClient = createWalletClient({ account, chain: NETWORK.chain, transport: http(NETWORK.rpcUrl) });
  const publicClient = createPublicClient({ chain: NETWORK.chain, transport: http(NETWORK.rpcUrl) });

  const hash = await walletClient.deployContract({
    abi: artifact.abi,
    bytecode: artifact.bytecode,
  });
  console.log("Deploy tx:", hash);

  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  console.log("\nRecoveryModule deployed:", receipt.contractAddress);
  console.log("\nAdd to .env.local:");
  console.log(`NEXT_PUBLIC_RECOVERY_MODULE_ADDRESS=${receipt.contractAddress}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
