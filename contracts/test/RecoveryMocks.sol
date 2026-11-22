// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// Test double of SafeWebAuthnSharedSigner: configure() writes into the CALLER's storage (it is
/// reached by DelegateCall from the Safe), at a fixed slot, like the real singleton.
contract MockSharedSigner {
    bytes32 internal constant SLOT = keccak256("mock.shared.signer.config");

    struct SignerConfig {
        uint256 x;
        uint256 y;
        uint176 verifiers;
    }

    function configure(SignerConfig calldata signer) external {
        bytes32 slot = SLOT;
        uint256 x = signer.x;
        uint256 y = signer.y;
        uint256 v = signer.verifiers;
        assembly {
            sstore(slot, x)
            sstore(add(slot, 1), y)
            sstore(add(slot, 2), v)
        }
    }
}

/// Test double of a Safe: enables one module, lets it execute (Call or DelegateCall), and lets the
/// test act AS the Safe (exec) to call module functions that use msg.sender == safe.
contract MockSafe {
    bytes32 internal constant SLOT = keccak256("mock.shared.signer.config");
    mapping(address => bool) public isModuleEnabled;

    function enableModule(address module) external {
        isModuleEnabled[module] = true;
    }

    function execTransactionFromModule(address to, uint256 value, bytes calldata data, uint8 operation)
        external
        returns (bool success)
    {
        require(isModuleEnabled[msg.sender], "GS104");
        if (operation == 1) (success,) = to.delegatecall(data);
        else (success,) = to.call{value: value}(data);
    }

    /// The test calls the module as this Safe (stands in for a UserOp signed by the current passkey).
    function exec(address to, bytes calldata data) external returns (bytes memory) {
        (bool ok, bytes memory ret) = to.call(data);
        if (!ok) {
            assembly {
                revert(add(ret, 32), mload(ret))
            }
        }
        return ret;
    }

    function signerConfig() external view returns (uint256 x, uint256 y, uint256 verifiers) {
        bytes32 slot = SLOT;
        assembly {
            x := sload(slot)
            y := sload(add(slot, 1))
            verifiers := sload(add(slot, 2))
        }
    }
}
