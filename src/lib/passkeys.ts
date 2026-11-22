import { extractPasskeyData, PasskeyArgType } from "@safe-global/protocol-kit";
import { PasskeyCoords } from "@/types";
import { PACKED_VERIFIERS_HEX } from "@/app/constants";
import { encodeAbiParameters, toBytes, toHex, type Hex } from "viem";

/**
 * Build the PasskeyArgType protocol-kit 8 expects. `verifiers` is the uint176 stored for this
 * passkey in the SharedSigner config (default: precompile + Daimo fallback). After a rotation, pass
 * the value read on-chain so the SDK's shared-signer check matches it exactly.
 */
export function toPasskeyArg(rawId: string, x: string, y: string, verifiers: string = PACKED_VERIFIERS_HEX): PasskeyArgType {
  return { rawId, coordinates: { x, y }, verifierAddress: verifiers };
}

/**
 * Create a P-256 passkey. `discoverable` (resident key) is used for a passkey that acts as recovery
 * authority: at recovery time it is found by the authenticator without knowing its rawId.
 */
export async function createPasskey(label: string, discoverable = false): Promise<{ passkey: PasskeyArgType; coords: PasskeyCoords }> {
  const credential = await navigator.credentials.create({
    publicKey: {
      pubKeyCredParams: [{ alg: -7, type: "public-key" }],
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      authenticatorSelection: discoverable
        ? { userVerification: "required", residentKey: "required", requireResidentKey: true }
        : { userVerification: "required" },
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

// P-256 group order and half, for low-S normalization (OpenZeppelin's P256 rejects high-S signatures).
const P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

/** Parse an ASN.1 DER ECDSA signature (WebAuthn assertions use DER) into low-S (r, s). */
function derToRS(der: Uint8Array): { r: bigint; s: bigint } {
  if (der[0] !== 0x30) throw new Error("Not a DER signature");
  let i = 2;
  if (der[i] !== 0x02) throw new Error("Bad DER (r)");
  const rLen = der[i + 1];
  const r = BigInt(toHex(der.slice(i + 2, i + 2 + rLen)));
  i = i + 2 + rLen;
  if (der[i] !== 0x02) throw new Error("Bad DER (s)");
  const sLen = der[i + 1];
  let s = BigInt(toHex(der.slice(i + 2, i + 2 + sLen)));
  if (s > P256_N / 2n) s = P256_N - s;
  return { r, s };
}

/**
 * Sign a 32-byte digest with a passkey and return the ERC-7913 WebAuthn signature expected by
 * OpenZeppelin's ERC7913WebAuthnVerifier: the six WebAuthnAuth fields abi-encoded from offset 0
 * (r, s, challengeIndex, typeIndex, authenticatorData, clientDataJSON). The challenge is the digest.
 * `rawId` (hex) selects the credential; without it, the authenticator offers its discoverable ones.
 */
export async function signDigestWithPasskey(digest: Hex, rawId?: string): Promise<{ signature: Hex; rawId: string }> {
  const credential = (await navigator.credentials.get({
    publicKey: {
      challenge: new Uint8Array(toBytes(digest)),
      allowCredentials: rawId ? [{ type: "public-key", id: new Uint8Array(toBytes(`0x${rawId.replace(/^0x/, "")}`)) }] : [],
      userVerification: "required", // the verifier requires the UV flag
      rpId: window.location.hostname,
      timeout: 60_000,
    },
  })) as PublicKeyCredential | null;
  if (!credential) throw new Error("Passkey signature cancelled");
  const res = credential.response as AuthenticatorAssertionResponse;
  const clientDataJSON = new TextDecoder().decode(res.clientDataJSON);
  const challengeIndex = clientDataJSON.indexOf('"challenge"');
  const typeIndex = clientDataJSON.indexOf('"type"');
  if (challengeIndex < 0 || typeIndex < 0) throw new Error("Unexpected clientDataJSON");
  const { r, s } = derToRS(new Uint8Array(res.signature));
  const signature = encodeAbiParameters(
    [
      { name: "r", type: "bytes32" }, { name: "s", type: "bytes32" },
      { name: "challengeIndex", type: "uint256" }, { name: "typeIndex", type: "uint256" },
      { name: "authenticatorData", type: "bytes" }, { name: "clientDataJSON", type: "string" },
    ],
    [
      toHex(r, { size: 32 }), toHex(s, { size: 32 }), BigInt(challengeIndex), BigInt(typeIndex),
      toHex(new Uint8Array(res.authenticatorData)), clientDataJSON,
    ],
  );
  return { signature, rawId: toHex(new Uint8Array(credential.rawId)).slice(2) };
}
