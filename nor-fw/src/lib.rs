//! 双槽 NOR 闪存固件更新模拟器（无第三方依赖）。
//!
//! 模块：
//! - [`layout`]：器件/槽/记录区布局与记录编码
//! - [`sha256`]：自包含 SHA-256
//! - [`flash`]：NOR 模型（1->0 编程语义）与掉电夹具
//! - [`package`]：更新包格式
//! - [`boot`]：启动检查（只读闪存记录）
//! - [`updater`]：更新器（只擦非当前槽 + 记录区换代）
//! - [`replay`]：全切口/换代掉电复演

pub mod boot;
pub mod flash;
pub mod layout;
pub mod package;
pub mod replay;
pub mod sha256;
pub mod updater;
