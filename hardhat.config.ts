import { HardhatUserConfig } from "hardhat/config";
import hardhatViem from "@nomicfoundation/hardhat-viem";
import hardhatNodeTestRunner from "@nomicfoundation/hardhat-node-test-runner";
import hardhatNetworkHelpers from "@nomicfoundation/hardhat-network-helpers";
import { config as dotenv } from "dotenv";
import { NETWORKS } from "./src/app/constants";

dotenv({ path: ".env.local" });

const config: HardhatUserConfig = {
  plugins: [hardhatViem, hardhatNodeTestRunner, hardhatNetworkHelpers],
  solidity: {
    // 0.8.24+ for OpenZeppelin 5.6 (ERC-7913 / WebAuthn); Cancun EVM (mcopy), live on Sepolia.
    version: "0.8.28",
    settings: { optimizer: { enabled: true, runs: 200 }, evmVersion: "cancun" },
  },
  networks: {
    // One entry per network in src/app/constants.ts (same keys as NETWORKS).
    ...Object.fromEntries(
      Object.values(NETWORKS).map((n) => [
        n.key,
        {
          type: "http" as const,
          url: n.rpcUrl,
          accounts: process.env.DEPLOYER_PRIVATE_KEY ? [process.env.DEPLOYER_PRIVATE_KEY] : [],
        },
      ]),
    ),
  },
};

export default config;
