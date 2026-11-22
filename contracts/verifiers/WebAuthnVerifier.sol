// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {ERC7913WebAuthnVerifier} from "@openzeppelin/contracts/utils/cryptography/verifiers/ERC7913WebAuthnVerifier.sol";

/// Exposes OpenZeppelin's stateless ERC-7913 WebAuthn verifier so tests and scripts can deploy it.
contract WebAuthnVerifier is ERC7913WebAuthnVerifier {}
