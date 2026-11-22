// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

// Minimal interface: Safe executes transactions from enabled modules
interface ISafe {
    function execTransactionFromModule(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation // 0 = CALL
    ) external returns (bool success);
}

// Mirrors the on-chain SafeWebAuthnSharedSigner singleton
interface ISharedSigner {
    struct SignerConfig {
        uint256 x;
        uint256 y;
        // Packed verifiers: upper 16 bits = precompile address, lower 160 bits = fallback verifier
        // Format: (uint176(precompile) << 160) | uint176(uint160(fallback))
        // P256.sol tries the precompile first, falls back if it returns empty
        uint176 verifiers;
    }

    // Stores signer config in the *calling Safe's* storage slot (must be called via DelegateCall)
    function configure(SignerConfig calldata signer) external;
}

/**
 * RecoveryModule: PoC passkey rotation via execTransactionFromModule
 *
 * Flow:
 *  1. Safe enables this module (enableModule UserOp)
 *  2. Safe calls setupRecovery(recoveryKey) to register a recovery EOA
 *  3. When rotating: recoveryKey signs an EIP-712 digest off-chain
 *     → anyone relays recover(safe, newX, newY, verifiers, sig)
 *     → this module calls SharedSigner.configure on behalf of the Safe
 * @dev Not audited.
 */
contract RecoveryModule {
    // SafeWebAuthnSharedSigner on Sepolia
    address public constant SHARED_SIGNER = 0x94a4F6affBd8975951142c3999aEAB7ecee555c2;


    bytes32 private constant TYPE_HASH = keccak256(
        "Recover(address safe,uint256 x,uint256 y,uint176 verifiers,uint256 nonce)"
    );

    bytes32 private constant DOMAIN_TYPE_HASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    mapping(address => address) public recoveryKeys; // safe => recovery EOA
    mapping(address => uint256) public nonces;       // anti-replay per safe

    event RecoverySetup(address indexed safe, address indexed recoveryKey);
    event RecoveryExecuted(address indexed safe);

    // Called by the Safe itself (via a Safe transaction / UserOp)
    function setupRecovery(address recoveryKey) external {
        require(recoveryKey != address(0), "RecoveryModule: zero address");
        recoveryKeys[msg.sender] = recoveryKey;
        emit RecoverySetup(msg.sender, recoveryKey);
    }

    // Permissionless relay: authorization is proven by the EIP-712 signature
    function recover(
        address safe,
        uint256 newX,
        uint256 newY,
        uint176 verifiers,
        bytes calldata signature
    ) external {
        address key = recoveryKeys[safe];
        require(key != address(0), "RecoveryModule: no recovery key");

        bytes32 structHash = keccak256(abi.encode(
            TYPE_HASH, safe, newX, newY, verifiers, nonces[safe]
        ));
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01", _domainSeparator(), structHash
        ));

        require(_ecrecover(digest, signature) == key, "RecoveryModule: bad signature");
        nonces[safe]++;

        // Call SharedSigner.configure via Safe's module execution channel
        bytes memory data = abi.encodeCall(
            ISharedSigner.configure,
            (ISharedSigner.SignerConfig(newX, newY, verifiers))
        );
        // DelegateCall (op=1) required: configure() stores the signer config in the
        // Safe's own storage slot, so it must execute in the Safe's context.
        bool ok = ISafe(safe).execTransactionFromModule(SHARED_SIGNER, 0, data, 1);
        require(ok, "RecoveryModule: execTransactionFromModule failed");

        emit RecoveryExecuted(safe);
    }

    function _domainSeparator() internal view returns (bytes32) {
        return keccak256(abi.encode(
            DOMAIN_TYPE_HASH,
            keccak256("RecoveryModule"),
            keccak256("1"),
            block.chainid,
            address(this)
        ));
    }

    function _ecrecover(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        require(sig.length == 65, "RecoveryModule: bad sig length");
        bytes32 r = bytes32(sig[:32]);
        bytes32 s = bytes32(sig[32:64]);
        uint8 v = uint8(sig[64]);
        return ecrecover(digest, v, r, s);
    }
}
