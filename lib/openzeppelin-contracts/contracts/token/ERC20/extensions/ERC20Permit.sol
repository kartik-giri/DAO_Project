// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (token/ERC20/extensions/ERC20Permit.sol)

pragma solidity ^0.8.20;

import {IERC20Permit} from "./IERC20Permit.sol";
import {ERC20} from "../ERC20.sol";
import {ECDSA} from "../../../utils/cryptography/ECDSA.sol";
import {EIP712} from "../../../utils/cryptography/EIP712.sol";
import {Nonces} from "../../../utils/Nonces.sol";

/**
 * @dev Implementation of the ERC20 Permit extension allowing approvals to be made via signatures, as defined in
 * https://eips.ethereum.org/EIPS/eip-2612[EIP-2612].
 *
 * Adds the {permit} method, which can be used to change an account's ERC20 allowance (see {IERC20-allowance}) by
 * presenting a message signed by the account. By not relying on `{IERC20-approve}`, the token holder account doesn't
 * need to send a transaction, and thus is not required to hold Ether at all.
 */

 // this allows approvals to be made via signatures. basically we can signed a tx without sending it and let somebody else send the tx.
abstract contract ERC20Permit is ERC20, IERC20Permit, EIP712, Nonces {
    bytes32 private constant PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    /**
     * @dev Permit deadline has expired.
     */
    error ERC2612ExpiredSignature(uint256 deadline);

    /**
     * @dev Mismatched signature.
     */
    error ERC2612InvalidSigner(address signer, address owner);

    /**
     * @dev Initializes the {EIP712} domain separator using the `name` parameter, and setting `version` to `"1"`.
     *
     * It's a good idea to use the same `name` that is defined as the ERC20 token name.
     */
    constructor(string memory name) EIP712(name, "1") {}

    /**
     * @inheritdoc IERC20Permit
     */
     // the function permit takes  owner, spender, value, v,r,s signature para and deadline for the last time that the signature is valid if the signature is 
     //valied than anyone can call this funciton to approve the spender to spend value amount of tokens from the owner and the signature will be signed by the owner.
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public virtual {
        if (block.timestamp > deadline) {
            revert ERC2612ExpiredSignature(deadline);
        }

        //PERMIT_TYPEHASH: This is a predefined constant representing a unique identifier for the permit function. It helps distinguish the type of operation being performed.
        //value that represents the number of transactions sent from a particular address (EOA - Externally Owned Account). Each time an EOA sends a transaction, 
        //its nonce increases by one. Nonces help prevent replay attacks and ensure the order and uniqueness of transactions sent by an account.
        bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, _useNonce(owner), deadline));

        // the line is taking the previously computed structHash and further processing it through a function called _hashTypedDataV4. This step is likely
        // part of a broader mechanism for handling typed data hashing, often used in Ethereum for structured data hashing according to the EIP-712 standard
        bytes32 hash = _hashTypedDataV4(structHash);

        //It uses the ECDSA.recover function to recover the Ethereum address (signer) from a provided hash (hash) and the components of an ECDSA signature: v, r, and s.
        address signer = ECDSA.recover(hash, v, r, s);
        if (signer != owner) {
            revert ERC2612InvalidSigner(signer, owner);
        }

        _approve(owner, spender, value);
    }
    //In summary, the permit function checks the validity of a permit signature, ensuring it is not expired and that the signer is the rightful owner. 
    //If the checks pass, it approves the spender to spend a certain value of tokens on behalf of the owner.
    // This mechanism allows token approvals to be made via a signed message, improving user experience and reducing the need for direct transactions.

    /**
     * @inheritdoc IERC20Permit
     */
    function nonces(address owner) public view virtual override(IERC20Permit, Nonces) returns (uint256) {
        return super.nonces(owner);
    }

    /**
     * @inheritdoc IERC20Permit
     */
    // solhint-disable-next-line func-name-mixedcase
    function DOMAIN_SEPARATOR() external view virtual returns (bytes32) {
        return _domainSeparatorV4();
    }
}
