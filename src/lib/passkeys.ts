import { extractPasskeyData, PasskeyArgType } from "@safe-global/protocol-kit";
import { PasskeyCoords } from "@/types";
import { PACKED_VERIFIERS_HEX } from "@/app/constants";

/**
 * Build the PasskeyArgType protocol-kit 8 expects. `verifiers` is the uint176 stored for this
 * passkey in the SharedSigner config (default: precompile + Daimo fallback). After a rotation, pass
 * the value read on-chain so the SDK's shared-signer check matches it exactly.
 */
export function toPasskeyArg(rawId: string, x: string, y: string, verifiers: string = PACKED_VERIFIERS_HEX): PasskeyArgType {
  return { rawId, coordinates: { x, y }, verifierAddress: verifiers };
}

export async function createPasskey(label: string): Promise<{ passkey: PasskeyArgType; coords: PasskeyCoords }> {
  const credential = await navigator.credentials.create({
    publicKey: {
      pubKeyCredParams: [{ alg: -7, type: "public-key" }],
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      authenticatorSelection: { userVerification: "required" },
      rp: { name: `poc-rotation-${label}`, id: window.location.hostname },
      user: {
        displayName: label,
        id: crypto.getRandomValues(new Uint8Array(32)),
        name: `${label}_${Date.now()}`,
      },
      timeout: 60_000,
      attestation: "none",
    },
  });

  if (!credential) throw new Error("Passkey creation failed");

  const extracted = await extractPasskeyData(credential);
  const passkey = toPasskeyArg(extracted.rawId, extracted.coordinates.x, extracted.coordinates.y);
  return {
    passkey,
    coords: { rawId: passkey.rawId, x: passkey.coordinates.x, y: passkey.coordinates.y },
  };
}

export async function loadPasskey(rawId: string): Promise<boolean> {
  try {
    const credential = await navigator.credentials.get({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        allowCredentials: [{ type: "public-key", id: new Uint8Array(Buffer.from(rawId, "hex")) }],
        userVerification: "required",
        timeout: 60_000,
      },
    });
    return !!credential;
  } catch {
    return false;
  }
}
