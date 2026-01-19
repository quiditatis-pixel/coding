// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Pausable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
* @title MyWeb3Token
* @dev 一个安全、可扩展的ERC20代币示例，适用于大多数Web3项目
* 包含：铸造、销毁、暂停、角色权限控制
*/
contract MyWeb3Token is ERC20, ERC20Burnable, ERC20Pausable, AccessControl, Ownable {

// 定义角色
bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

// 代币最大供应量（可选，设为0表示无上限）
uint256 public constant MAX_SUPPLY = 1_000_000_000 * 10**18; // 10亿枚

constructor(
string memory name,
string memory symbol,
address initialOwner
) ERC20(name, symbol) Ownable(initialOwner) {
// 授予部署者所有角色
_grantRole(DEFAULT_ADMIN_ROLE, initialOwner);
_grantRole(MINTER_ROLE, initialOwner);
_grantRole(PAUSER_ROLE, initialOwner);

// 初始铸造给项目方（可选）
_mint(initialOwner, 100_000_000 * 10**18); // 初始1亿枚
}

/**
* @dev 铸造新代币（仅限MINTER_ROLE）
*/
function mint(address to, uint256 amount) public onlyRole(MINTER_ROLE) {
require(totalSupply() + amount <= MAX_SUPPLY, "Exceeds max supply");
_mint(to, amount);
}

/**
* @dev 暂停所有转账（紧急情况使用）
*/
function pause() public onlyRole(PAUSER_ROLE) {
_pause();
}

/**
* @dev 取消暂停
*/
function unpause() public onlyRole(PAUSER_ROLE) {
_unpause();
}

// 重写以下函数以支持Pausable功能
function _update(address from, address to, uint256 value)
internal
override(ERC20, ERC20Pausable)
{
super._update(from, to, value);
}

// AccessControl 的接口支持声明
function supportsInterface(bytes4 interfaceId)
public
view
override(AccessControl)
returns (bool)
{
return super.supportsInterface(interfaceId);
}
}

