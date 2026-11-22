// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

/// Minimal Safe interface: a module executes through the Safe.
interface ISafeModuleExec {
    function execTransactionFromModule(address to, uint256 value, bytes calldata data, uint8 operation)
        external
        returns (bool success);
}

/// SafeWebAuthnSharedSigner: stores (x, y, verifiers) in the CALLING Safe's storage, so it must be
/// reached through a DelegateCall from the Safe.
interface ISharedSigner {
    struct SignerConfig {
        uint256 x;
        uint256 y;
        uint176 verifiers;
    }

    function configure(SignerConfig calldata signer) external;
}

/**
 * @title RecoveryAuthorityModule
 * @notice Safe module that rotates the passkey of a SafeWebAuthnSharedSigner Safe after a delay,
 *         authorized by a pluggable recovery authority.
 *
 * The authority is an ERC-7913 signer (`bytes`): 20 bytes = an address (EOA via ecrecover, or a
 * contract via ERC-1271); longer = `verifier || key`, checked with IERC7913SignatureVerifier
 * (e.g. a P-256 / WebAuthn verifier with key = qx || qy).
 *
 * Flow, per Safe:
 *   1. setupRecovery(signer, delay)            called BY the Safe (its current passkey)
 *   2. request(safe, x, y, verifiers, sig)     anyone relays; sig by the authority over an EIP-712 Rotate
 *   3. cancel()                                called BY the Safe while the request is pending
 *   4. execute(safe)                           anyone, once `delay` has elapsed
 *
 * Invariants:
 *   - The passkey config of a Safe only changes through execute(), never earlier than
 *     requestedAt + delay, and only for a request that was not cancelled.
 *   - Each authority signature is single-use: it binds the per-Safe nonce, the chain id and this
 *     module (EIP-712 domain), and request() consumes the nonce.
 *
 * Not in this module (next layers): a guard that delays loosening changes (including setupRecovery
 * itself), an escape to a pre-committed address, growing deposits on requests, M-of-N guardians.
 */
contract RecoveryAuthorityModule is EIP712 {
    using SignatureChecker for bytes;

    /// SafeWebAuthnSharedSigner singleton (same address on every network).
    address public immutable SHARED_SIGNER;
    /// Lower bound for the per-Safe delay.
    uint64 public immutable MIN_DELAY;

    uint8 private constant OPERATION_DELEGATECALL = 1;

    bytes32 private constant ROTATE_TYPEHASH =
        keccak256("Rotate(address safe,uint256 x,uint256 y,uint176 verifiers,uint256 nonce)");

    struct Pending {
        uint256 x;
        uint256 y;
        uint176 verifiers;
        uint64 executeAfter; // 0 = no pending request
    }

    /// ERC-7913 recovery signer per Safe (empty = recovery disabled).
    mapping(address safe => bytes signer) public recoverySigner;
    /// Delay between request and execute, per Safe.
    mapping(address safe => uint64 delay) public recoveryDelay;
    /// Single-use counter bound into every authority signature.
    mapping(address safe => uint256 nonce) public nonces;
    /// At most one pending rotation per Safe.
    mapping(address safe => Pending pending) public pendingRotation;

    /// `signerHash` = keccak256(signer). For an address signer it is keccak256(abi.encodePacked(addr)),
    /// which lets a holder of the recovery key find its Safe from the logs.
    event RecoverySetup(address indexed safe, bytes32 indexed signerHash, bytes signer, uint64 delay);
    event RecoveryDisabled(address indexed safe);
    event RotationRequested(address indexed safe, uint256 nonce, uint256 x, uint256 y, uint176 verifiers, uint64 executeAfter);
    event RotationCancelled(address indexed safe);
    event RotationExecuted(address indexed safe, uint256 x, uint256 y, uint176 verifiers);

    error DelayTooShort(uint64 delay, uint64 minDelay);
    error InvalidSigner();
    error RecoveryNotSetUp();
    error RotationAlreadyPending();
    error NoPendingRotation();
    error TooEarly(uint64 executeAfter);
    error InvalidAuthoritySignature();
    error ConfigureFailed();

    constructor(address sharedSigner, uint64 minDelay) EIP712("RecoveryAuthorityModule", "1") {
        SHARED_SIGNER = sharedSigner;
        MIN_DELAY = minDelay;
    }

    // ── Setup (called by the Safe) ──────────────────────────────────────────────────────────

    /// @notice Register (or replace) the recovery authority of `msg.sender` (the Safe).
    /// Replacing it drops any pending rotation, which was authorized by the previous authority.
    function setupRecovery(bytes calldata signer, uint64 delay) external {
        if (signer.length < 20) revert InvalidSigner();
        if (delay < MIN_DELAY) revert DelayTooShort(delay, MIN_DELAY);
        recoverySigner[msg.sender] = signer;
        recoveryDelay[msg.sender] = delay;
        if (pendingRotation[msg.sender].executeAfter != 0) {
            delete pendingRotation[msg.sender];
            emit RotationCancelled(msg.sender);
        }
        emit RecoverySetup(msg.sender, keccak256(signer), signer, delay);
    }

    /// @notice Disable recovery for `msg.sender` (tightening: immediate). Drops any pending rotation.
    function disableRecovery() external {
        delete recoverySigner[msg.sender];
        delete recoveryDelay[msg.sender];
        if (pendingRotation[msg.sender].executeAfter != 0) {
            delete pendingRotation[msg.sender];
            emit RotationCancelled(msg.sender);
        }
        emit RecoveryDisabled(msg.sender);
    }

    // ── Rotation lifecycle ──────────────────────────────────────────────────────────────────

    /// @notice EIP-712 digest the recovery authority signs for the next rotation of `safe`.
    function rotateDigest(address safe, uint256 x, uint256 y, uint176 verifiers) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(ROTATE_TYPEHASH, safe, x, y, verifiers, nonces[safe])));
    }

    /// @notice Start a rotation to the passkey (x, y, verifiers). Anyone can relay it.
    function request(address safe, uint256 x, uint256 y, uint176 verifiers, bytes calldata signature) external {
        bytes memory signer = recoverySigner[safe];
        if (signer.length == 0) revert RecoveryNotSetUp();
        if (pendingRotation[safe].executeAfter != 0) revert RotationAlreadyPending();

        bytes32 digest = rotateDigest(safe, x, y, verifiers);
        if (!signer.isValidSignatureNow(digest, signature)) revert InvalidAuthoritySignature();

        uint256 usedNonce = nonces[safe]++;
        uint64 executeAfter = uint64(block.timestamp) + recoveryDelay[safe];
        pendingRotation[safe] = Pending({x: x, y: y, verifiers: verifiers, executeAfter: executeAfter});
        emit RotationRequested(safe, usedNonce, x, y, verifiers, executeAfter);
    }

    /// @notice Cancel the pending rotation of `msg.sender` (the Safe, i.e. its current passkey).
    function cancel() external {
        if (pendingRotation[msg.sender].executeAfter == 0) revert NoPendingRotation();
        delete pendingRotation[msg.sender];
        emit RotationCancelled(msg.sender);
    }

    /// @notice Apply the pending rotation of `safe` once its delay has elapsed. Anyone can call it.
    function execute(address safe) external {
        Pending memory p = pendingRotation[safe];
        if (p.executeAfter == 0) revert NoPendingRotation();
        if (block.timestamp < p.executeAfter) revert TooEarly(p.executeAfter);
        delete pendingRotation[safe];

        bytes memory data = abi.encodeCall(
            ISharedSigner.configure, (ISharedSigner.SignerConfig({x: p.x, y: p.y, verifiers: p.verifiers}))
        );
        if (!ISafeModuleExec(safe).execTransactionFromModule(SHARED_SIGNER, 0, data, OPERATION_DELEGATECALL)) {
            revert ConfigureFailed();
        }
        emit RotationExecuted(safe, p.x, p.y, p.verifiers);
    }
}
