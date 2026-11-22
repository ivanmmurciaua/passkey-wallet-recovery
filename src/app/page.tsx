"use client";

import { useState } from "react";
import { PocState, StepStatus } from "@/types";
import { createPasskey, toPasskeyArg } from "@/lib/passkeys";
import { isAddress, toHex } from "viem";
import { initSafe, loadExistingSafe, sendUserOp } from "@/lib/wallet";
import {
  encodeEnableModule,
  encodeSetupRecovery,
  encodeRecover,
  generateRecoveryKey,
  getRecoveryNonce,
  getRecoveryKey,
  findSafesByRecoveryKey,
  getSharedSignerConfig,
  isModuleEnabled,
  signRecovery,
  defaultVerifiers,
} from "@/lib/recovery";
import { RECOVERY_MODULE_ADDRESS } from "@/app/constants";
import { exportKRecovery, importKRecovery } from "@/lib/keybackup";
import { privateKeyToAccount } from "viem/accounts";
import { PasskeyArgType } from "@safe-global/protocol-kit";
import { Safe4337Pack } from "@safe-global/relay-kit";

const empty: PocState = {
  safeAddress: "",
  passkeyA: null,
  moduleEnabled: false,
  recoveryAddress: "",
  recoveryPrivateKey: "",
  recoverySetup: false,
  passkeyB: null,
  rotationDone: false,
  verifiedConfig: null,
  verificationPassed: null,
  loginOk: false,
};

type Log = { ts: string; msg: string; err?: boolean };

function ts() {
  return new Date().toISOString().slice(11, 23);
}

function downloadJson(filename: string, text: string) {
  const blob = new Blob([text], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

// Where step 3 obtains the recovery key again.
type RestoreSource = "backup" | "paste";

/** Validate a 0x + 64-hex secp256k1 private key and return it with its address. */
function toRecoveryKey(k: string): { privateKey: `0x${string}`; address: `0x${string}` } {
  const key = k.trim();
  if (!/^0x[0-9a-fA-F]{64}$/.test(key)) throw new Error("The recovery key must be 0x + 64 hex chars");
  const privateKey = key.toLowerCase() as `0x${string}`;
  return { privateKey, address: privateKeyToAccount(privateKey).address }; // throws on an invalid scalar
}

export default function PocPage() {
  const [state, setState] = useState<PocState>(empty);
  const [packA, setPackA] = useState<Safe4337Pack | null>(null);
  const [logs, setLogs] = useState<Log[]>([]);
  const [statuses, setStatuses] = useState<Record<string, StepStatus>>({});
  const [recoveryKeyInput, setRecoveryKeyInput] = useState("");

  // Encrypted backup of the recovery key: offered after step 2, consumed in step 3.
  const [restoreSource, setRestoreSource] = useState<RestoreSource>("backup");
  const [backupPwd, setBackupPwd] = useState("");
  const [importFileText, setImportFileText] = useState("");
  const [importPwd, setImportPwd] = useState("");
  // Step 3 must work from a fresh session (the real "lost device" case): the Safe address can be
  // typed in, and everything else is read from the chain, not from steps 1-2 of this session.
  const [s3SafeAddress, setS3SafeAddress] = useState("");
  const recoverSafe = (s3SafeAddress.trim() || state.safeAddress).trim();

  // Import fields for existing credentials (Step 1 Option A)
  const [importSafeAddress, setImportSafeAddress] = useState("");
  const [importRawId, setImportRawId] = useState("");
  const [importX, setImportX] = useState("");
  const [importY, setImportY] = useState("");

  // Step 6: standalone fields (Passkey B + Safe address)
  const [s6SafeAddress, setS6SafeAddress] = useState("");
  const [s6RawId, setS6RawId] = useState("");
  const [s6X, setS6X] = useState("");
  const [s6Y, setS6Y] = useState("");

  function log(msg: string, err = false) {
    setLogs((prev) => [...prev, { ts: ts(), msg, err }]);
  }

  function setStatus(step: string, s: StepStatus) {
    setStatuses((prev) => ({ ...prev, [step]: s }));
  }

  // ── Import existing credentials ──────────────────────────────────────────

  async function loadExisting() {
    setStatus("s1", "loading");
    try {
      if (!importSafeAddress || !importRawId || !importX || !importY) {
        throw new Error("Fill in all four fields: Safe address, rawId, X, Y");
      }

      log("Loading existing Safe with provided credentials...");
      const passkey: PasskeyArgType = toPasskeyArg(importRawId.trim(), importX.trim(), importY.trim());
      const coords = { rawId: importRawId.trim(), x: importX.trim(), y: importY.trim() };

      // Use initSafe: computes the deterministic address from passkey coords.
      // No safeAddress option needed: protocol-kit derives it from owners/threshold.
      let pack = await initSafe(passkey);
      const resolvedAddress = await pack.protocolKit.getAddress();
      log(`Computed Safe address: ${resolvedAddress}`);

      if (resolvedAddress.toLowerCase() !== importSafeAddress.trim().toLowerCase()) {
        throw new Error(`Address mismatch: wrong credentials? Expected ${importSafeAddress.trim()}, got ${resolvedAddress}`);
      }

      log("Checking if RecoveryModule is already enabled...");
      let moduleEnabled = false;
      try {
        moduleEnabled = await isModuleEnabled(resolvedAddress);
        log(`Module enabled: ${moduleEnabled ? "✓ yes" : "✗ no"}`);
      } catch {
        log("Safe not deployed yet: will deploy + enable via first UserOp");
      }

      if (!moduleEnabled) {
        if (!RECOVERY_MODULE_ADDRESS) {
          throw new Error("NEXT_PUBLIC_RECOVERY_MODULE_ADDRESS not set");
        }
        log("Enabling RecoveryModule via UserOp (also deploys Safe if not yet deployed)...");
        const hash = await sendUserOp(pack, [
          {
            to: resolvedAddress,
            data: encodeEnableModule(RECOVERY_MODULE_ADDRESS),
            value: "0",
          },
        ]);
        log(`Module enabled. userOpHash: ${hash}`);

        // Re-init so protocol-kit picks up the deployed Safe's SharedSigner config
        log("Re-initializing pack (Safe now deployed, switching to SharedSigner path)...");
        const passkey: PasskeyArgType = toPasskeyArg(importRawId.trim(), importX.trim(), importY.trim());
        pack = await initSafe(passkey);
        moduleEnabled = true;
      }

      setPackA(pack);
      setState((s) => ({ ...s, safeAddress: resolvedAddress, passkeyA: coords, moduleEnabled }));
      setStatus("s1", "done");
    } catch (e: unknown) {
      log(e instanceof Error ? e.message : String(e), true);
      setStatus("s1", "error");
    }
  }

  // ── Step 1: Deploy Safe + Enable Module ──────────────────────────────────

  async function step1() {
    setStatus("s1", "loading");
    try {
      log("Creating Passkey A...");
      const { passkey, coords } = await createPasskey("passkey-A");
      log(`Passkey A rawId: ${coords.rawId}`);
      log(`Passkey A X: ${coords.x}`);
      log(`Passkey A Y: ${coords.y}`);

      log("Initializing Safe4337Pack...");
      const pack = await initSafe(passkey);
      const safeAddress = await pack.protocolKit.getAddress();
      log(`Safe address: ${safeAddress}`);
      setPackA(pack);
      setState((s) => ({ ...s, safeAddress, passkeyA: coords }));

      if (!RECOVERY_MODULE_ADDRESS) {
        throw new Error("NEXT_PUBLIC_RECOVERY_MODULE_ADDRESS not set: run the deploy script first");
      }

      log("Sending UserOp: enableModule(RecoveryModule)...");
      const hash = await sendUserOp(pack, [
        {
          to: safeAddress,
          data: encodeEnableModule(RECOVERY_MODULE_ADDRESS),
          value: "0",
        },
      ]);
      log(`Module enabled. userOpHash: ${hash}`);

      // Re-init pack now that the Safe is deployed: protocol-kit will now find
      // the SharedSigner config on-chain and use the correct signer path.
      log("Re-initializing pack (Safe deployed, switching to SharedSigner path)...");
      const deployedPack = await initSafe(passkey);
      setPackA(deployedPack);

      setState((s) => ({ ...s, moduleEnabled: true }));
      setStatus("s1", "done");
    } catch (e: unknown) {
      log(e instanceof Error ? e.message : String(e), true);
      setStatus("s1", "error");
    }
  }

  // ── Step 2: Setup Recovery Key ───────────────────────────────────────────

  async function step2() {
    setStatus("s2", "loading");
    try {
      if (!packA || !state.safeAddress) throw new Error("Complete Step 1 first");

      log("Generating recovery key...");
      const { privateKey, address } = generateRecoveryKey();
      log(`Recovery address: ${address}`);
      setState((s) => ({ ...s, recoveryAddress: address, recoveryPrivateKey: privateKey }));

      log("Sending UserOp: setupRecovery(recoveryKey)...");
      const hash = await sendUserOp(packA, [
        {
          to: RECOVERY_MODULE_ADDRESS,
          data: encodeSetupRecovery(address),
          value: "0",
        },
      ]);
      log(`UserOp hash: ${hash}`);

      // The public RPC is load-balanced: a node behind the one that served the receipt can still
      // return the old value (seen on Sepolia: 0x0 right after a successful setupRecovery).
      // Re-read for a few seconds before concluding there is a mismatch.
      log("Verifying on-chain: recoveryKeys[safe]...");
      let storedKey = await getRecoveryKey(state.safeAddress);
      for (let i = 0; i < 10 && storedKey.toLowerCase() !== address.toLowerCase(); i++) {
        await new Promise((r) => setTimeout(r, 1500));
        storedKey = await getRecoveryKey(state.safeAddress);
      }
      log(`Stored recovery key: ${storedKey}`);
      if (storedKey.toLowerCase() !== address.toLowerCase()) {
        throw new Error(`On-chain key mismatch: expected ${address}, got ${storedKey}`);
      }
      log("On-chain recovery key verified ✓");
      setState((s) => ({ ...s, recoverySetup: true }));
      setStatus("s2", "done");
    } catch (e: unknown) {
      log(e instanceof Error ? e.message : String(e), true);
      setStatus("s2", "error");
    }
  }

  async function downloadBackup() {
    try {
      if (!state.recoveryPrivateKey) throw new Error("No recovery key in memory");
      if (!backupPwd) throw new Error("Enter a password for the backup");
      log("Encrypting the recovery key (Argon2id + AES-256-GCM)...");
      const blob = await exportKRecovery(state.recoveryPrivateKey, backupPwd);
      downloadJson("recovery-key-backup.json", blob);
      log("Encrypted recovery key backup downloaded");
    } catch (e: unknown) {
      log(e instanceof Error ? e.message : String(e), true);
    }
  }

  // ── Step 3: Rotate Passkey ───────────────────────────────────────────────

  async function step3() {
    setStatus("s3", "loading");
    try {
      let safe = recoverSafe;
      if (safe && !isAddress(safe)) throw new Error("The Safe address is not valid");
      if (restoreSource === "backup" && (!importFileText || !importPwd)) throw new Error("Load the backup file and enter its password");
      if (restoreSource === "paste") toRecoveryKey(recoveryKeyInput); // fail fast, before creating Passkey B

      // Obtain the recovery key and check it against the one registered on-chain BEFORE creating
      // Passkey B or signing anything: a wrong password or another Safe's backup stops here.
      let K: string;
      if (restoreSource === "backup") {
        log("Decrypting the backup file with its password...");
        K = await importKRecovery(importFileText, importPwd);
        log("Recovery key recovered from the encrypted backup.");
      } else {
        K = recoveryKeyInput;
      }
      const recovery = toRecoveryKey(K);
      if (!safe) {
        // No address given: find the Safe from the recovery key itself (RecoverySetup events).
        log(`Looking up the Safe whose recovery key is ${recovery.address}...`);
        const safes = await findSafesByRecoveryKey(recovery.address);
        if (safes.length === 0) throw new Error("No Safe currently has this recovery key registered. Enter the Safe address.");
        if (safes.length > 1) throw new Error(`This recovery key protects several Safes: ${safes.join(", ")}. Enter the one to recover.`);
        safe = safes[0];
        log(`Found Safe: ${safe}`);
      }
      const registered = await getRecoveryKey(safe);
      if (/^0x0{40}$/i.test(registered)) throw new Error(`No recovery key is registered for ${safe}`);
      if (recovery.address.toLowerCase() !== registered.toLowerCase()) {
        throw new Error(`This recovery key is ${recovery.address}, but the Safe has ${registered} registered`);
      }
      log(`Recovery key matches the one registered on-chain (${registered}) ✓`);

      log("Creating Passkey B (new passkey)...");
      const { coords } = await createPasskey("passkey-B");
      log(`Passkey B rawId: ${coords.rawId}`);
      log(`Passkey B X: ${coords.x}`);
      log(`Passkey B Y: ${coords.y}`);
      setState((s) => ({ ...s, passkeyB: coords }));

      log("Reading SharedSigner config BEFORE rotation...");
      const currentConfig = await getSharedSignerConfig(safe);
      log(`Current X (Passkey A): ${currentConfig.x.toString()}`);
      log(`Current Y (Passkey A): ${currentConfig.y.toString()}`);
      log(`Current verifiers: ${currentConfig.verifiers.toString()}`);

      // Always upgrade to PACKED_VERIFIERS (precompile 0x0100 + Daimo fallback).
      // This migrates the Safe to the EIP-7951 precompile regardless of what it had before.
      const verifiers = defaultVerifiers();
      log(`Verifiers for Passkey B: ${verifiers.toString()} (precompile 0x0100 + Daimo fallback; same as the deploy)`);

      log("Reading nonce from RecoveryModule...");
      const nonce = await getRecoveryNonce(safe);
      log(`Nonce: ${nonce}`);

      log("Signing EIP-712 recovery digest with recovery key...");
      const signature = await signRecovery({
        privateKey: recovery.privateKey,
        safeAddress: safe,
        newX: BigInt(coords.x),
        newY: BigInt(coords.y),
        verifiers,
        nonce,
      });
      log(`Signature: ${signature}`);

      log("Initializing Safe B (0x3) to send the UserOp...");
      const passkeyB: PasskeyArgType = toPasskeyArg(coords.rawId, coords.x, coords.y);
      const packB = await initSafe(passkeyB);
      const addrB = await packB.protocolKit.getAddress();
      log(`Safe B (0x3) address: ${addrB}`);

      log("Sending UserOp from Safe B (0x3): recover(0x1, newX, newY, verifiers, sig): sponsored by Pimlico...");
      const userOpHash = await sendUserOp(packB, [
        {
          to: RECOVERY_MODULE_ADDRESS,
          data: encodeRecover({
            safeAddress: safe,
            newX: BigInt(coords.x),
            newY: BigInt(coords.y),
            verifiers,
            signature,
          }),
          value: "0",
        },
      ]);
      log(`UserOp hash: ${userOpHash}`);
      setState((s) => ({ ...s, safeAddress: safe, rotationDone: true }));
      setStatus("s3", "done");
    } catch (e: unknown) {
      log(e instanceof Error ? e.message : String(e), true);
      setStatus("s3", "error");
    }
  }

  // ── Step 4: Verify ───────────────────────────────────────────────────────

  async function step4() {
    setStatus("s4", "loading");
    try {
      if (!state.safeAddress || !state.passkeyB) throw new Error("Complete Steps 1-3 first");

      log("Reading SharedSigner config AFTER rotation...");
      const config = await getSharedSignerConfig(state.safeAddress);
      log(`On-chain X:  ${config.x.toString()}`);
      log(`Passkey B X: ${state.passkeyB.x}`);
      log(`On-chain Y:  ${config.y.toString()}`);
      log(`Passkey B Y: ${state.passkeyB.y}`);

      const xMatch = config.x === BigInt(state.passkeyB.x);
      const yMatch = config.y === BigInt(state.passkeyB.y);
      const passed = xMatch && yMatch;

      log(`X match: ${xMatch ? "✓" : "✗"}  Y match: ${yMatch ? "✓" : "✗"}`);
      setState((s) => ({ ...s, verifiedConfig: config, verificationPassed: passed }));
      setStatus("s4", "done");
    } catch (e: unknown) {
      log(e instanceof Error ? e.message : String(e), true);
      setStatus("s4", "error");
    }
  }

  // ── Step 5: Login with Passkey B ────────────────────────────────────────

  async function step5() {
    setStatus("s5", "loading");
    try {
      if (!state.passkeyB) throw new Error("Complete Step 3 first");

      log("Loading existing Safe 0x1 with Passkey B credentials...");
      log(`rawId: ${state.passkeyB.rawId}`);
      log(`X: ${state.passkeyB.x}`);
      log(`Y: ${state.passkeyB.y}`);
      log(`Target Safe: ${state.safeAddress}`);

      const passkey: PasskeyArgType = toPasskeyArg(state.passkeyB.rawId, state.passkeyB.x, state.passkeyB.y);
      const packB = await loadExistingSafe(passkey, state.safeAddress);
      const addr = await packB.protocolKit.getAddress();

      log(`Safe address resolved: ${addr}`);
      log(`Expected:              ${state.safeAddress}`);

      const match = addr.toLowerCase() === state.safeAddress.toLowerCase();
      log(`Address matches: ${match ? "✓ PASS" : "✗ FAIL"}`);
      log(match ? "Passkey B can operate Safe 0x1 ✓" : "Mismatch: something went wrong ✗", !match);
      setState((s) => ({ ...s, loginOk: match }));
      setStatus("s5", "done");
    } catch (e: unknown) {
      log(e instanceof Error ? e.message : String(e), true);
      setStatus("s5", "error");
    }
  }

  // ── Step 6: Send dummy UserOp from Passkey B on Safe 0x1 ────────────────

  async function step6() {
    setStatus("s6", "loading");
    try {
      if (!s6SafeAddress || !s6RawId || !s6X || !s6Y) {
        throw new Error("Fill in all four fields");
      }

      const passkey: PasskeyArgType = toPasskeyArg(s6RawId.trim(), s6X.trim(), s6Y.trim());

      log(`Safe: ${s6SafeAddress.trim()}`);
      log(`rawId: ${s6RawId.trim()}`);
      log(`X: ${s6X.trim()}`);
      log(`Y: ${s6Y.trim()}`);

      // Determine if rotated: initSafe computes counterfactual address from passkey coords.
      // If it matches → not rotated → use initSafe (correct gas estimation).
      // If it doesn't match → rotated (Passkey B) → use loadExistingSafe (PACKED_VERIFIERS → precompile).
      log("Computing counterfactual address via initSafe...");
      const packInit = await initSafe(passkey);
      const counterfactual = await packInit.protocolKit.getAddress();
      log(`Counterfactual address: ${counterfactual}`);

      let pack: Safe4337Pack;
      if (counterfactual.toLowerCase() === s6SafeAddress.trim().toLowerCase()) {
        log("✓ Address matches: passkey NOT rotated → using initSafe pack");
        pack = packInit;
      } else {
        log("↻ Address differs: passkey ROTATED → using loadExistingSafe");

        // Read the verifiers stored on-chain for this Safe and pass them as the passkey's
        // verifierAddress: protocol-kit 8 compares the full uint176 in its shared-signer check.
        log("Reading on-chain verifiers...");
        const onChainConfig = await getSharedSignerConfig(s6SafeAddress.trim());
        const onChainVerifiers = toHex(onChainConfig.verifiers);
        log(`On-chain verifiers: ${onChainVerifiers}`);

        const passkeyWithVerifier = toPasskeyArg(s6RawId.trim(), s6X.trim(), s6Y.trim(), onChainVerifiers);
        pack = await loadExistingSafe(passkeyWithVerifier, s6SafeAddress.trim());
      }

      const addr = await pack.protocolKit.getAddress();
      log(`Resolved Safe: ${addr}`);

      if (addr.toLowerCase() !== s6SafeAddress.trim().toLowerCase()) {
        throw new Error(`Address mismatch: expected ${s6SafeAddress.trim()}, got ${addr}`);
      }

      log("Reading SharedSigner config to check rotation status...");
      const onChain = await getSharedSignerConfig(s6SafeAddress.trim());
      const xMatch = onChain.x === BigInt(s6X.trim());
      const yMatch = onChain.y === BigInt(s6Y.trim());
      const isSigner = xMatch && yMatch;
      log(`On-chain X:  ${onChain.x.toString()}`);
      log(`Input X:     ${BigInt(s6X.trim()).toString()}`);
      log(`On-chain Y:  ${onChain.y.toString()}`);
      log(`Input Y:     ${BigInt(s6Y.trim()).toString()}`);

      // Decode verifiers field
      const MASK_160 = (1n << 160n) - 1n;
      const verifiers = onChain.verifiers;
      const precompileBits = verifiers >> 160n;
      const fallbackBits = verifiers & MASK_160;
      log(`On-chain verifiers (raw): ${verifiers.toString()}`);
      log(`  → precompile slot (upper 16 bits): 0x${precompileBits.toString(16).padStart(4, "0")} ${precompileBits === 0x0100n ? "✓ EIP-7951 precompile" : precompileBits === 0n ? "(none: simple encoding)" : "(unknown precompile)"}`);
      log(`  → fallback address (lower 160 bits): 0x${fallbackBits.toString(16).padStart(40, "0")}`);

      log(
        isSigner
          ? "✓ This passkey IS the current signer: Safe not rotated (or rotated TO this passkey)"
          : "⚠ This passkey is NOT the current signer: Safe has been rotated to different credentials",
        !isSigner,
      );

      log("Sending dummy UserOp: 0 ETH → 0xdead...");
      const userOpHash = await sendUserOp(pack, [
        {
          to: "0x000000000000000000000000000000000000dEaD",
          data: "0x",
          value: "0",
        },
      ]);
      log(`UserOp hash: ${userOpHash}`);
      log("UserOp executed successfully ✓");
      setStatus("s6", "done");
    } catch (e: unknown) {
      log(e instanceof Error ? e.message : String(e), true);
      setStatus("s6", "error");
    }
  }

  const icon = (s: StepStatus) =>
    s === "done" ? "✓" : s === "error" ? "✗" : s === "loading" ? "⟳" : "○";

  return (
    <div style={{ fontFamily: "monospace", padding: "24px", maxWidth: "720px", margin: "0 auto" }}>
      <h1 style={{ borderBottom: "1px solid #ccc", paddingBottom: "8px" }}>
        PoC: Passkey Rotation via RecoveryModule
      </h1>
      <p style={{ color: "#666", fontSize: "13px" }}>
        SharedSigner: <code>0x94a4F6...5c2</code> · Module:{" "}
        <code>{RECOVERY_MODULE_ADDRESS || "⚠ not configured"}</code>
      </p>

      {/* Step 1 */}
      <section style={sectionStyle}>
        <h2>{icon(statuses["s1"])} Step 1: Load or Deploy Safe + Enable RecoveryModule</h2>

        <p style={{ fontWeight: "bold", marginBottom: "4px" }}>Option A: Import existing credentials</p>
        <div style={{ display: "grid", gap: "4px", marginBottom: "8px" }}>
          {[
            ["Safe address", importSafeAddress, setImportSafeAddress, "0x..."],
            ["Passkey rawId", importRawId, setImportRawId, "hex string"],
            ["Passkey X", importX, setImportX, "decimal or hex"],
            ["Passkey Y", importY, setImportY, "decimal or hex"],
          ].map(([label, value, setter, placeholder]) => (
            <div key={label as string}>
              <label style={{ fontSize: "12px" }}>{label as string}:</label>
              <input
                type="text"
                placeholder={placeholder as string}
                value={value as string}
                onChange={(e) => (setter as (v: string) => void)(e.target.value)}
                style={{ width: "100%", fontFamily: "monospace", fontSize: "12px", padding: "3px", marginTop: "2px" }}
              />
            </div>
          ))}
        </div>
        <button onClick={loadExisting} disabled={statuses["s1"] === "loading" || !!state.safeAddress} style={btnStyle}>
          {statuses["s1"] === "loading" ? "Loading..." : "Load existing Safe"}
        </button>

        <hr style={{ margin: "12px 0", borderColor: "#eee" }} />

        <p style={{ fontWeight: "bold", marginBottom: "4px" }}>Option B: Create new Safe from scratch</p>
        <p style={{ fontSize: "13px", color: "#666" }}>Creates Passkey A, deploys a Safe, and enables the RecoveryModule in one UserOp.</p>
        <button onClick={step1} disabled={statuses["s1"] === "loading" || !!state.safeAddress} style={btnStyle}>
          {statuses["s1"] === "loading" ? "Working..." : "Deploy & Enable"}
        </button>

        {state.safeAddress && <p style={{ marginTop: "8px" }}>Safe: <code>{state.safeAddress}</code></p>}
        {state.moduleEnabled && <p style={okStyle}>Module enabled ✓</p>}
        {statuses["s1"] === "done" && !state.moduleEnabled && (
          <p style={{ color: "#c80" }}>⚠ Module not yet enabled: run &quot;Deploy &amp; Enable&quot; or enable it manually via UserOp.</p>
        )}
      </section>

      {/* Step 2 */}
      <section style={sectionStyle}>
        <h2>{icon(statuses["s2"])} Step 2: Setup Recovery Key</h2>
        <p>Generates a random recovery EOA and registers it on the RecoveryModule via UserOp.</p>
        {state.recoveryAddress && (
          <>
            <p>Recovery address: <code>{state.recoveryAddress}</code></p>
            <p style={{ color: "#c00" }}>
              ⚠ Save this private key: you need it in Step 3:<br />
              <code style={{ wordBreak: "break-all" }}>{state.recoveryPrivateKey}</code>
            </p>
          </>
        )}
        {state.recoverySetup && <p style={okStyle}>Recovery configured ✓</p>}
        <button onClick={step2} disabled={!state.moduleEnabled || statuses["s2"] === "loading" || state.recoverySetup} style={btnStyle}>
          {statuses["s2"] === "loading" ? "Working..." : "Generate & Setup"}
        </button>
        {state.recoverySetup && state.recoveryPrivateKey && (
          <div style={{ marginTop: "10px", fontSize: "13px" }}>
            <p>Download an encrypted backup of the recovery key (Argon2id + AES-256-GCM). Step 3 can restore it with the password.</p>
            <input type="password" placeholder="backup password" value={backupPwd} onChange={(e) => setBackupPwd(e.target.value)} style={{ fontFamily: "monospace", padding: "4px", marginRight: "6px" }} />
            <button onClick={downloadBackup} style={btnStyle}>Download encrypted backup</button>
          </div>
        )}
      </section>

      {/* Step 3 */}
      <section style={sectionStyle}>
        <h2>{icon(statuses["s3"])} Step 3: Rotate Passkey (simulate lost device)</h2>
        <p>Obtains the recovery key (backup or pasted), checks it against the one registered on-chain, creates Passkey B, signs the recovery digest and relays the rotation. Works in a fresh session: the recovery key alone is enough, the Safe is found from its on-chain RecoverySetup event.</p>
        <div style={{ margin: "8px 0" }}>
          <label style={{ fontSize: "13px" }}>Safe to recover (optional):</label>
          <br />
          <input
            type="text"
            placeholder={state.safeAddress || "0x... (optional: found from the recovery key if empty)"}
            value={s3SafeAddress}
            onChange={(e) => setS3SafeAddress(e.target.value)}
            disabled={state.rotationDone}
            style={{ width: "100%", fontFamily: "monospace", fontSize: "12px", padding: "4px", marginTop: "4px" }}
          />
        </div>
        <div style={{ margin: "8px 0", fontSize: "13px" }}>
          <label><input type="radio" checked={restoreSource === "backup"} onChange={() => setRestoreSource("backup")} disabled={state.rotationDone} /> Encrypted backup file + password</label>
          <br />
          <label><input type="radio" checked={restoreSource === "paste"} onChange={() => setRestoreSource("paste")} disabled={state.rotationDone} /> Paste the private key</label>
        </div>
        {restoreSource === "backup" ? (
          <div style={{ margin: "8px 0", fontSize: "13px" }}>
            <input type="file" accept="application/json" onChange={async (e) => setImportFileText((await e.target.files?.[0]?.text()) ?? "")} />
            <br />
            <input type="password" placeholder="backup password" value={importPwd} onChange={(e) => setImportPwd(e.target.value)} style={{ fontFamily: "monospace", padding: "4px", marginTop: "6px" }} />
          </div>
        ) : (
          <div style={{ margin: "8px 0" }}>
            <label style={{ fontSize: "13px" }}>Recovery private key (from Step 2):</label>
            <br />
            <input
              type="text"
              placeholder="0x..."
              value={recoveryKeyInput}
              onChange={(e) => setRecoveryKeyInput(e.target.value)}
              style={{ width: "100%", fontFamily: "monospace", fontSize: "12px", padding: "4px", marginTop: "4px" }}
            />
          </div>
        )}
        {state.passkeyB && <p>Passkey B created ✓ x={state.passkeyB.x.slice(0, 16)}...</p>}
        {state.rotationDone && <p style={okStyle}>Rotation complete ✓</p>}
        <button onClick={step3} disabled={(recoverSafe !== "" && !isAddress(recoverSafe)) || statuses["s3"] === "loading" || state.rotationDone} style={btnStyle}>
          {statuses["s3"] === "loading" ? "Working..." : "Rotate Passkey"}
        </button>
      </section>

      {/* Step 4 */}
      <section style={sectionStyle}>
        <h2>{icon(statuses["s4"])} Step 4: Verify On-Chain Config</h2>
        <p>Reads SharedSigner storage and confirms coordinates match Passkey B.</p>
        {state.verifiedConfig && (
          <p>
            X match: {state.verifiedConfig.x === BigInt(state.passkeyB?.x ?? "0") ? "✓" : "✗"} ·
            Y match: {state.verifiedConfig.y === BigInt(state.passkeyB?.y ?? "0") ? "✓" : "✗"}
          </p>
        )}
        {state.verificationPassed !== null && (
          <p style={state.verificationPassed ? okStyle : errStyle}>
            {state.verificationPassed ? "Verification PASSED ✓" : "Verification FAILED ✗"}
          </p>
        )}
        <button onClick={step4} disabled={!state.rotationDone || statuses["s4"] === "loading"} style={btnStyle}>
          {statuses["s4"] === "loading" ? "Reading..." : "Verify"}
        </button>
      </section>

      {/* Step 5 */}
      <section style={sectionStyle}>
        <h2>{icon(statuses["s5"])} Step 5: Login with Passkey B</h2>
        <p>
          Initializes a new Safe4337Pack using Passkey B. The deterministic Safe address must match the
          original Safe deployed in Step 1.
        </p>
        <p style={{ fontSize: "12px", color: "#888" }}>
          Note: This step creates another credential prompt. In a real app Passkey B would be loaded
          by rawId: for the PoC we create a fresh one to trigger the browser authenticator.
        </p>
        {state.loginOk && <p style={okStyle}>Login with Passkey B: PASS ✓</p>}
        <button onClick={step5} disabled={!state.verificationPassed || statuses["s5"] === "loading"} style={btnStyle}>
          {statuses["s5"] === "loading" ? "Loading..." : "Login with Passkey B"}
        </button>
      </section>

      {/* Step 6 */}
      <section style={sectionStyle}>
        <h2>{icon(statuses["s6"])} Step 6: Send UserOp with Passkey B on Safe 0x1 (standalone)</h2>
        <p>
          Usa <code>loadExistingSafe(passkeyB, safeAddress)</code> para enviar una tx real (0 ETH → 0xdead).
          Prueba si el problema de <code>verificationGasLimit</code> aparece en producción.
          Independiente de Steps 1-5.
        </p>
        <div style={{ display: "grid", gap: "4px", marginBottom: "8px" }}>
          {[
            ["Safe address (0x1)", s6SafeAddress, setS6SafeAddress, "0x..."],
            ["Passkey B rawId", s6RawId, setS6RawId, "hex string"],
            ["Passkey B X", s6X, setS6X, "0x... or decimal"],
            ["Passkey B Y", s6Y, setS6Y, "0x... or decimal"],
          ].map(([label, value, setter, placeholder]) => (
            <div key={label as string}>
              <label style={{ fontSize: "12px" }}>{label as string}:</label>
              <input
                type="text"
                placeholder={placeholder as string}
                value={value as string}
                onChange={(e) => (setter as (v: string) => void)(e.target.value)}
                style={{ width: "100%", fontFamily: "monospace", fontSize: "12px", padding: "3px", marginTop: "2px" }}
              />
            </div>
          ))}
        </div>
        {statuses["s6"] === "done" && <p style={okStyle}>UserOp executed with Passkey B on Safe 0x1 ✓</p>}
        <button onClick={step6} disabled={statuses["s6"] === "loading"} style={btnStyle}>
          {statuses["s6"] === "loading" ? "Working..." : "Send dummy UserOp"}
        </button>
      </section>

      {/* Log console */}
      <section style={{ marginTop: "24px" }}>
        <h2>Console</h2>
        <div
          style={{
            background: "#111",
            color: "#eee",
            padding: "12px",
            borderRadius: "4px",
            height: "240px",
            overflowY: "auto",
            fontSize: "12px",
          }}
        >
          {logs.length === 0 && <span style={{ color: "#666" }}>_ waiting for actions</span>}
          {logs.map((l, i) => (
            <div key={i} style={{ color: l.err ? "#f66" : "#eee" }}>
              <span style={{ color: "#666" }}>[{l.ts}]</span> {l.msg}
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}

const sectionStyle: React.CSSProperties = {
  border: "1px solid #ddd",
  borderRadius: "4px",
  padding: "16px",
  marginTop: "16px",
};

const btnStyle: React.CSSProperties = {
  marginTop: "8px",
  padding: "8px 16px",
  fontFamily: "monospace",
  cursor: "pointer",
};

const okStyle: React.CSSProperties = { color: "#0a0", fontWeight: "bold" };
const errStyle: React.CSSProperties = { color: "#c00", fontWeight: "bold" };
