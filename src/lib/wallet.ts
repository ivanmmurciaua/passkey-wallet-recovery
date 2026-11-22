import { PasskeyArgType } from "@safe-global/protocol-kit";
import { createBundlerClient, PaymasterOptions, PimlicoFeeEstimator, Safe4337Pack, userOperationToHexValues } from "@safe-global/relay-kit";
import { toHex } from "viem";
import {
  BUNDLER_URL,
  ENTRYPOINT_ADDRESS,
  PAYMASTER_URL,
  RPC_URL,
  SAFE_MODULES_ADDRESS,
  SAFE_MODULES_VERSION,
  SAFE_SW_VERSION,
} from "@/app/constants";

// WebAuthn validation gas varies per signature: browsers (Chrome) randomly add an extra key to
// clientDataJSON ("other_keys_can_be_added_here"), which the Safe must hash and parse on-chain.
// The bundler estimates with a short dummy signature, so a real signature can exceed its
// verificationGasLimit (seen on Sepolia: estimate 61.5K, real validation above it -> bundler
// "Internal error"). Add this margin to the account's verificationGasLimit.
export const VERIFICATION_GAS_MARGIN = 60_000n;

/**
 * Pimlico estimator with a verification-gas margin. The margin is applied BEFORE the paymaster
 * signs (its signature covers the gas limits), using ERC-7677 pm_getPaymasterData, which signs the
 * given limits as-is instead of re-estimating them.
 */
class MarginFeeEstimator extends PimlicoFeeEstimator {
  async postEstimateUserOperationGas(props: Parameters<PimlicoFeeEstimator["postEstimateUserOperationGas"]>[0]) {
    const { userOperation, entryPoint, paymasterOptions, protocolKit } = props;
    const verificationGasLimit = BigInt(userOperation.verificationGasLimit) + VERIFICATION_GAS_MARGIN;
    if (!paymasterOptions?.isSponsored) return { verificationGasLimit: verificationGasLimit.toString() };
    const op = { ...userOperation, verificationGasLimit };
    const client = createBundlerClient(paymasterOptions.paymasterUrl);
    const chainId = await protocolKit.getChainId();
    const pm = (await client.request({
      method: "pm_getPaymasterData" as never,
      params: [userOperationToHexValues(op, entryPoint), entryPoint, toHex(chainId), {}] as never,
    })) as Record<string, string>;
    return { ...pm, verificationGasLimit: verificationGasLimit.toString() };
  }
}

const paymasterOptions: PaymasterOptions = {
  isSponsored: true,
  paymasterUrl: PAYMASTER_URL,
};

export async function initSafe(passkey: PasskeyArgType): Promise<Safe4337Pack> {
  return Safe4337Pack.init({
    provider: RPC_URL,
    signer: passkey,
    bundlerUrl: BUNDLER_URL,
    safeModulesVersion: SAFE_MODULES_VERSION,
    customContracts: {
      entryPointAddress: ENTRYPOINT_ADDRESS,
      safe4337ModuleAddress: SAFE_MODULES_ADDRESS,
    },
    paymasterOptions,
    options: {
      safeVersion: SAFE_SW_VERSION,
      owners: [],
      threshold: 1,
    },
  });
}

// Load an existing Safe by address using a new passkey (post-rotation login)
export async function loadExistingSafe(passkey: PasskeyArgType, safeAddress: string): Promise<Safe4337Pack> {
  return Safe4337Pack.init({
    provider: RPC_URL,
    signer: passkey,
    bundlerUrl: BUNDLER_URL,
    safeModulesVersion: SAFE_MODULES_VERSION,
    customContracts: {
      entryPointAddress: ENTRYPOINT_ADDRESS,
      safe4337ModuleAddress: SAFE_MODULES_ADDRESS,
    },
    paymasterOptions,
    options: {
      safeVersion: SAFE_SW_VERSION,
      safeAddress,
    },
  });
}

// Load a Safe that a UserOp has just deployed. Behind a load-balanced RPC the next read can hit a
// node that does not see the new code yet ("SafeProxy contract is not deployed"), so retry.
export async function loadJustDeployedSafe(passkey: PasskeyArgType, safeAddress: string): Promise<Safe4337Pack> {
  for (let attempt = 1; ; attempt++) {
    try {
      return await loadExistingSafe(passkey, safeAddress);
    } catch (e) {
      if (attempt >= 10) throw e;
      await new Promise((r) => setTimeout(r, 1500));
    }
  }
}

export async function sendUserOp(
  pack: Safe4337Pack,
  transactions: { to: string; data: string; value: string }[],
): Promise<string> {
  const safeOp = await pack.createTransaction({ transactions, options: { feeEstimator: new MarginFeeEstimator() } });
  const signedOp = await pack.signSafeOperation(safeOp);
  const userOpHash = await pack.executeTransaction({ executable: signedOp });

  let receipt = null;
  let attempts = 0;
  while (!receipt && attempts < 30) {
    await new Promise((r) => setTimeout(r, 2000));
    receipt = await pack.getUserOperationReceipt(userOpHash);
    attempts++;
  }

  if (!receipt) throw new Error("UserOp timed out after 60s");
  if (!receipt.success) throw new Error("UserOp failed");

  return userOpHash;
}
