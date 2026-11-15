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
  // Step 2
  recoveryAddress: string;
  recoveryPrivateKey: string;
  recoverySetup: boolean;
  // Step 3
  passkeyB: PasskeyCoords | null;
  rotationDone: boolean;
  // Step 4
  verifiedConfig: SignerConfig | null;
  verificationPassed: boolean | null;
  // Step 5
  loginOk: boolean;
};
