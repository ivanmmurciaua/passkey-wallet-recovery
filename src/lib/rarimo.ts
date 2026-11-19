import { UnforgettableSdk, RecoveryFactor } from "@rarimo/unforgettable-sdk";
import { NotFoundError } from "@distributedlab/jac";
import { privateKeyToAccount } from "viem/accounts";
import { createPublicClient, http, parseAbi } from "viem";
import { RARIMO } from "@/app/constants";

export { RecoveryFactor };

// ── Enrollment confirmation on Rarimo L2 ────────────────────────────────
// Rarimo's SDK can hand back K_recovery locally the instant the app posts it,
// BEFORE the helper-keeper backend has durably committed the enrollment. Trusting
// that early is exactly what left RESTORE returning "no helper accounts found":
// CREATE looked done, the key was shown, but nothing was persisted to recover
// from. The durable source of truth is on Rarimo L2: the HelperDataFactory
// stores an AccountInfo per enrolled account, and its `metadata` is non-zero only
// once the enrollment is committed. So we confirm there before trusting the key.
const ZERO32 = `0x${"0".repeat(64)}` as const;

const helperDataFactoryAbi = parseAbi([
  "struct AccountInfo { address account; uint64 subscriptionEndTime; bytes32 metadata; }",
  "function getAccountInfo(address account_) view returns (AccountInfo)",
]);

const rarimoL2 = createPublicClient({ transport: http(RARIMO.l2Rpc) });

// True once the enrollment for `recoveryAddress` (= addr(K_recovery)) is durably
// committed on Rarimo L2. Registration ⟺ AccountInfo.metadata != 0x0.
export async function isRarimoEnrolled(recoveryAddress: string): Promise<boolean> {
  const info = await rarimoL2.readContract({
    address: RARIMO.helperDataFactory,
    abi: helperDataFactoryAbi,
    functionName: "getAccountInfo",
    args: [recoveryAddress as `0x${string}`],
  });
  return info.metadata !== ZERO32;
}

// Poll Rarimo L2 until the enrollment is confirmed on-chain, or the retry budget
// runs out. Must be awaited AFTER CREATE returns K_recovery and BEFORE the key is
// shown / a backup is offered / the user is told setup succeeded: a failed budget
// means CREATE did not persist and the key must not be trusted.
//
// Resilient by design: Rarimo L2 blocks are ~15s, so confirmation lags CREATE by
// a block or more, and l2.rarimo.com can hiccup. Each poll is one attempt whether
// metadata is still 0x0 or the read threw: neither aborts early; only exhausting
// all `maxAttempts` fails. Defaults ≈ 24 attempts × 5s ≈ 2 min (~8 blocks).
export async function waitForRarimoEnrollment(
  recoveryAddress: string,
  { maxAttempts = 24, intervalMs = 5000 }: { maxAttempts?: number; intervalMs?: number } = {},
): Promise<void> {
  let lastErr: unknown = null;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      if (await isRarimoEnrolled(recoveryAddress)) return;
      lastErr = null;
    } catch (e) {
      // Transient RPC/read failure: don't abort; this attempt just counts as "not yet".
      lastErr = e;
    }
    if (attempt < maxAttempts) await new Promise((r) => setTimeout(r, intervalMs));
  }
  const why = lastErr instanceof Error ? ` (last error: ${lastErr.message})` : "";
  throw new Error(
    `Rarimo enrollment not confirmed on-chain after ${maxAttempts} attempts (metadata unset): ` +
      `CREATE did not persist. Do not trust K_recovery; retry the recovery setup.${why}`,
  );
}

// Domain separator for K_recovery derivation (see RARIMO.group in constants.ts).
export const RARIMO_GROUP = RARIMO.group;

// K_recovery from Rarimo is a 0x + 64-hex secp256k1 private key. Validate the
// format defensively before trusting it as the recovery key (and let viem confirm
// it derives a valid account / scalar).
export function kRecoveryToOwner(kRecovery: string): {
  privateKey: `0x${string}`;
  address: `0x${string}`;
} {
  const k = kRecovery.trim();
  if (!/^0x[0-9a-fA-F]{64}$/.test(k)) {
    throw new Error(
      `K_recovery is not a 0x+64-hex secp256k1 key (got length ${k.length})`,
    );
  }
  const privateKey = k.toLowerCase() as `0x${string}`;
  const account = privateKeyToAccount(privateKey); // throws if not a valid scalar
  return { privateKey, address: account.address };
}

// Thin driver around the core SDK (A2: no React package). Builds the recovery
// URL (render it as a QR) and polls until the Rarimo app posts the encrypted
// K_recovery, which the SDK decrypts locally with its ephemeral key.
export interface RarimoSession {
  url: string;
  /** Begin polling. Resolves with K_recovery; rejects on error or cancel. */
  waitForKey: () => Promise<string>;
  /** Stop polling (e.g. user cancels the QR view). */
  cancel: () => void;
}

export async function startRarimo(
  mode: "create" | "restore",
  factors: RecoveryFactor[],
  walletAddress?: string,
  pollingIntervalMs = 3000,
): Promise<RarimoSession> {
  // Per Rarimo's official react example: walletAddress is the disambiguator that
  // lets RESTORE locate the enrollment. It equals addr(K_recovery): i.e. our
  // recovery EOA address (registered on-chain via setupRecovery). CREATE sends
  // none; RESTORE must send it or Rarimo can't find the key to return.
  const sdk = new UnforgettableSdk({
    mode,
    factors,
    group: RARIMO_GROUP,
    walletAddress: mode === "restore" ? walletAddress || undefined : undefined,
  });
  const url = await sdk.getRecoveryUrl();

  let timer: ReturnType<typeof setInterval> | null = null;
  let onVisible: (() => void) | null = null;
  let cancelled = false;
  const stop = () => {
    if (timer) clearInterval(timer);
    timer = null;
    if (onVisible) {
      document.removeEventListener("visibilitychange", onVisible);
      onVisible = null;
    }
  };

  const waitForKey = () =>
    new Promise<string>((resolve, reject) => {
      const poll = async () => {
        if (cancelled || !timer) return;
        try {
          const key = await sdk.getRecoveredKey();
          stop();
          resolve(key);
        } catch (e) {
          // NotFoundError = transfer not ready yet → keep polling.
          if (e instanceof NotFoundError) return;
          stop();
          reject(e as Error);
        }
      };
      timer = setInterval(poll, pollingIntervalMs);
      // Same-device (mobile): the user leaves to the Rarimo app and comes back.
      // Background tabs throttle timers, so poll immediately on return to the tab.
      onVisible = () => {
        if (document.visibilityState === "visible") poll();
      };
      document.addEventListener("visibilitychange", onVisible);
    });

  return {
    url,
    waitForKey,
    cancel: () => {
      cancelled = true;
      stop();
    },
  };
}
