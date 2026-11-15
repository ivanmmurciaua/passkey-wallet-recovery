// Fail-loud check of src/app/constants.ts, per network:
//  1. every canonical address matches the official Safe deployment registries for the pinned versions;
//  2. every address has code on-chain (and the SafeL2 singleton of VERSIONS.safe is deployed);
//  3. the P256VERIFY precompile answers a freshly signed P-256 vector with 1.
// Usage: npm run check:constants            (all networks)
//        npm run check:constants -- sepolia (one network)
import { createPublicClient, http, concat, numberToHex, sha256, toHex, type Address } from "viem";
import { p256 } from "@noble/curves/nist.js";
import {
  getSafe4337ModuleDeployment,
  getSafeModuleSetupDeployment,
  getSafeWebAuthnShareSignerDeployment,
  getSafeWebAuthnSignerFactoryDeployment,
  getDaimoP256VerifierDeployment,
} from "@safe-global/safe-modules-deployments";
import { getSafeL2SingletonDeployment, getProxyFactoryDeployment } from "@safe-global/safe-deployments";
import { CANONICAL, NETWORKS, P256_PRECOMPILE, VERSIONS, type NetworkConfig, type NetworkKey } from "../src/app/constants";

type Lookup = (f: { version: string; network: string; released: boolean }) => { networkAddresses: Record<string, string | string[]> } | undefined;

let failures = 0;
const ok = (msg: string) => console.log(`  [OK]   ${msg}`);
const bad = (msg: string) => { failures++; console.log(`  [FAIL] ${msg}`); };

function registryAddress(lookup: Lookup, version: string, chainId: number): string | null {
  const d = lookup({ version, network: String(chainId), released: true });
  const a = d?.networkAddresses[String(chainId)];
  return a ? (Array.isArray(a) ? a[0] : a) : null;
}

async function checkNetwork(n: NetworkConfig) {
  console.log(`\n${n.key} (chain ${n.chain.id}, ${n.p256Precompile})`);
  const client = createPublicClient({ chain: n.chain, transport: http(n.rpcUrl) });
  const id = n.chain.id;

  const expected: [string, Address, Lookup, string][] = [
    ["safe4337Module", CANONICAL.safe4337Module, getSafe4337ModuleDeployment as Lookup, VERSIONS.safe4337Module],
    ["safeModuleSetup", CANONICAL.safeModuleSetup, getSafeModuleSetupDeployment as Lookup, VERSIONS.safe4337Module],
    ["webAuthnSharedSigner", CANONICAL.webAuthnSharedSigner, getSafeWebAuthnShareSignerDeployment as Lookup, VERSIONS.safePasskeyModule],
    ["webAuthnSignerFactory", CANONICAL.webAuthnSignerFactory, getSafeWebAuthnSignerFactoryDeployment as Lookup, VERSIONS.safePasskeyModule],
    ["daimoP256Verifier", CANONICAL.daimoP256Verifier, getDaimoP256VerifierDeployment as Lookup, VERSIONS.safePasskeyModule],
  ];
  for (const [name, addr, lookup, version] of expected) {
    const reg = registryAddress(lookup, version, id);
    if (!reg) bad(`${name}: not in the registry for v${version} on chain ${id}`);
    else if (reg.toLowerCase() !== addr.toLowerCase()) bad(`${name}: constants ${addr} != registry ${reg}`);
    else ok(`${name} v${version} matches the registry`);
  }

  // Safe singleton and proxy factory of the pinned Safe version must exist on this chain.
  for (const [name, lookup] of [["SafeL2", getSafeL2SingletonDeployment], ["SafeProxyFactory", getProxyFactoryDeployment]] as const) {
    const reg = registryAddress(lookup as unknown as Lookup, VERSIONS.safe, id);
    if (!reg) bad(`${name} v${VERSIONS.safe}: not deployed on chain ${id} per the registry`);
    else expected.push([`${name} v${VERSIONS.safe}`, reg as Address, lookup as unknown as Lookup, VERSIONS.safe]);
  }

  // Code on-chain for everything, plus the EntryPoint and our RecoveryModule.
  const withCode: [string, Address][] = [
    ["entryPoint v" + VERSIONS.entryPoint, CANONICAL.entryPoint],
    ...expected.map(([name, addr]) => [name, addr] as [string, Address]),
  ];
  if (n.recoveryModule) withCode.push(["RecoveryModule", n.recoveryModule]);
  else console.log("  [--]   RecoveryModule: not deployed on this network yet");
  for (const [name, addr] of withCode) {
    try {
      const code = await client.getCode({ address: addr });
      if (code && code !== "0x") ok(`${name} has code at ${addr}`);
      else bad(`${name}: no code at ${addr}`);
    } catch (e) {
      bad(`${name}: could not read code (${e instanceof Error ? e.message : e})`);
    }
  }

  // P256VERIFY: input = hash(32) || r(32) || s(32) || x(32) || y(32); output = 32-byte 1 on success.
  try {
    const sk = p256.utils.randomSecretKey();
    const pk = p256.getPublicKey(sk, false); // 0x04 || x || y
    const hash = sha256(toHex("p256-precompile-check"));
    const signed = p256.sign(Buffer.from(hash.slice(2), "hex"), sk, { prehash: false }) as unknown;
    // @noble/curves returns raw bytes or a Signature object depending on the version.
    const sig: Uint8Array = signed instanceof Uint8Array
      ? signed
      : (signed as { toBytes?: (f: string) => Uint8Array; toCompactRawBytes?: () => Uint8Array }).toBytes?.("compact")
        ?? (signed as { toCompactRawBytes: () => Uint8Array }).toCompactRawBytes();
    const input = concat([hash, toHex(sig.slice(0, 32)), toHex(sig.slice(32, 64)), toHex(pk.slice(1, 33)), toHex(pk.slice(33, 65))]);
    const precompile = numberToHex(P256_PRECOMPILE, { size: 20 });
    const res = await client.call({ to: precompile, data: input });
    if (res.data && BigInt(res.data) === 1n) ok(`P256VERIFY at ${precompile} verified a fresh signature`);
    else bad(`P256VERIFY at ${precompile}: returned ${res.data ?? "empty"} (precompile missing?)`);
  } catch (e) {
    bad(`P256VERIFY call failed (${e instanceof Error ? e.message : e})`);
  }
}

async function main() {
  const only = process.argv[2] as NetworkKey | undefined;
  const list = only ? [NETWORKS[only]].filter(Boolean) : Object.values(NETWORKS);
  if (list.length === 0) throw new Error(`unknown network: ${only}`);
  for (const n of list) await checkNetwork(n);
  console.log(failures === 0 ? "\nALL CONSTANTS OK" : `\n${failures} CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main();
