import { HardhatUserConfig } from "hardhat/config";
import hardhatViem from "@nomicfoundation/hardhat-viem";
import { config as dotenv } from "dotenv";
import { NETWORKS } from "./src/app/constants";

dotenv({ path: ".env.local" });

const config: HardhatUserConfig = {
  plugins: [hardhatViem],
  solidity: {
    version: "0.8.20",
    settings: { optimizer: { enabled: true, runs: 200 } },
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
