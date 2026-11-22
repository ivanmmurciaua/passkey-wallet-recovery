export type PasskeyCoords = {
  rawId: string;
  x: string;
  y: string;
};

export type SignerConfig = {
  x: bigint;
  y: bigint;
  verifiers: bigint;
};

export type StepStatus = "idle" | "loading" | "done" | "error";

export type PocState = {
  // Step 1
  safeAddress: string;
  passkeyA: PasskeyCoords | null;
  moduleEnabled: boolean;
  // Step 2: the recovery authority, always the user's own (a key with an encrypted backup, or a second passkey)
  recoveryKind: "key" | "passkey" | null;
  recoveryAddress: string;
  recoveryPrivateKey: string;
  recoveryPasskey: PasskeyCoords | null;
  recoverySetup: boolean;
  // Step 3: rotation requested, executable after the delay
  passkeyB: PasskeyCoords | null;
  requestDone: boolean;
  executeAfter: string; // unix seconds, as string ("" = none)
  // Step 4 (execute)
  rotationDone: boolean;
  // Step 4
  verifiedConfig: SignerConfig | null;
  verificationPassed: boolean | null;
  // Step 5
  loginOk: boolean;
};
