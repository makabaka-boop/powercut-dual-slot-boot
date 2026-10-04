//! 更新包格式：固定 40 字节头 + 固件载荷。
//!
//! 头（大端）：
//! ```text
//! 0..8   魔数 b"FWPKG001"
//! 8..12  版本（u32，必须递增）
//! 12..16 载荷长度（u32）
//! 16..48 载荷 SHA-256
//! 48..   载荷
//! ```

use crate::sha256::sha256;

pub const PKG_MAGIC: [u8; 8] = *b"FWPKG001";
pub const PKG_HEADER_LEN: usize = 48;

/// 解析后的更新包
#[derive(Debug, Clone)]
pub struct Package {
    pub version: u32,
    pub data: Vec<u8>,
    pub hash: [u8; 32],
}

impl Package {
    pub fn new(version: u32, data: Vec<u8>) -> Self {
        let hash = sha256(&data);
        Package {
            version,
            data,
            hash,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PKG_HEADER_LEN + self.data.len());
        out.extend_from_slice(&PKG_MAGIC);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&(self.data.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.hash);
        out.extend_from_slice(&self.data);
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Package, String> {
        if buf.len() < PKG_HEADER_LEN {
            return Err("更新包过短".into());
        }
        if buf[0..8] != PKG_MAGIC {
            return Err("更新包魔数错误".into());
        }
        let version = u32::from_be_bytes(buf[8..12].try_into().unwrap());
        let len = u32::from_be_bytes(buf[12..16].try_into().unwrap()) as usize;
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&buf[16..48]);
        if buf.len() != PKG_HEADER_LEN + len {
            return Err(format!(
                "更新包长度不一致：头声明 {len}，实际 {}",
                buf.len() - PKG_HEADER_LEN
            ));
        }
        let data = buf[PKG_HEADER_LEN..].to_vec();
        if sha256(&data) != hash {
            return Err("更新包载荷 SHA-256 校验失败".into());
        }
        Ok(Package {
            version,
            data,
            hash,
        })
    }
}
