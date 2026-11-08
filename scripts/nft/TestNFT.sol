// SPDX-License-Identifier: MIT
// Minimal ERC-721 used only to test near-policy-vault on Sepolia: anyone can mint, no metadata.
// Compiled with solc 0.8.37 (optimizer on, 200 runs); bytecode in TestNFT.json.
pragma solidity ^0.8.20;

interface IERC721Receiver {
    function onERC721Received(address operator, address from, uint256 tokenId, bytes calldata data)
        external
        returns (bytes4);
}

contract TestNFT {
    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);

    string public constant name = "Policy Vault Test NFT";
    string public constant symbol = "PVTNFT";
    uint256 public nextId;
    mapping(uint256 => address) private owners;
    mapping(address => uint256) private balances;
    mapping(uint256 => address) private approvals;
    mapping(address => mapping(address => bool)) private operators;

    function supportsInterface(bytes4 id) external pure returns (bool) {
        return id == 0x80ac58cd || id == 0x01ffc9a7; // ERC-721, ERC-165
    }

    function mint(address to) external returns (uint256 id) {
        require(to != address(0), "zero address");
        id = nextId++;
        owners[id] = to;
        balances[to] += 1;
        emit Transfer(address(0), to, id);
    }

    function ownerOf(uint256 id) public view returns (address o) {
        o = owners[id];
        require(o != address(0), "no such token");
    }

    function balanceOf(address a) external view returns (uint256) {
        return balances[a];
    }

    function getApproved(uint256 id) external view returns (address) {
        return approvals[id];
    }

    function isApprovedForAll(address o, address op) external view returns (bool) {
        return operators[o][op];
    }

    function approve(address to, uint256 id) external {
        address o = ownerOf(id);
        require(msg.sender == o || operators[o][msg.sender], "not allowed");
        approvals[id] = to;
        emit Approval(o, to, id);
    }

    function setApprovalForAll(address op, bool ok) external {
        operators[msg.sender][op] = ok;
        emit ApprovalForAll(msg.sender, op, ok);
    }

    function transferFrom(address from, address to, uint256 id) public {
        address o = ownerOf(id);
        require(o == from, "wrong from");
        require(to != address(0), "zero address");
        require(msg.sender == o || approvals[id] == msg.sender || operators[o][msg.sender], "not allowed");
        delete approvals[id];
        balances[from] -= 1;
        balances[to] += 1;
        owners[id] = to;
        emit Transfer(from, to, id);
    }

    function safeTransferFrom(address from, address to, uint256 id) external {
        transferFrom(from, to, id);
        if (to.code.length > 0) {
            require(
                IERC721Receiver(to).onERC721Received(msg.sender, from, id, "") == IERC721Receiver.onERC721Received.selector,
                "receiver refused"
            );
        }
    }
}
