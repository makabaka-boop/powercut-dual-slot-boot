//! 闪存布局与记录编码。
//!
//! 整个器件（模拟）布局：
//! - 槽 0 / 槽 1：各 32 KiB 固件槽（每槽 8 个 4 KiB 擦除扇区）
//! - 记录区：2 个 4 KiB 扇区，循环换代
//!
//! 发布记录是定长 104 字节的结构。固件数据先完整编程并逐字节读回核验，
//! 随后才在记录区写入记录；记录本体带 SHA-256，commit 魔数最后编程。
//! 因此读回时可以区分「已完整发布」与「掉电中断的半包」：
//! - commit 魔数不完整 → 未提交（忽略）
//! - 本体 SHA-256 不符 → 本体被撕碎（忽略）
//! - 两者都成立        → 完整发布记录
//!
//! 记录里不存换代号：记录所在扇区的头部记录了该代的编号；只有头部
//! 已激活（commit 完整）的扇区，其中的记录才参与启动选择。

/// 擦除扇区大小：4 KiB
pub const SECTOR_SIZE: usize = 4096;
/// 编程页大小：256 字节
pub const PAGE_SIZE: usize = 256;
/// 每个固件槽大小：32 KiB
pub const SLOT_SIZE: usize = 32 * 1024;
/// 固件槽数量
pub const NUM_SLOTS: usize = 2;
/// 每个槽的擦除扇区数
pub const SECTORS_PER_SLOT: usize = SLOT_SIZE / SECTOR_SIZE; // 8
/// 记录区扇区数量（两代轮转）
pub const NUM_REC_SECTORS: usize = 2;
/// 总扇区数
pub const TOTAL_SECTORS: usize = NUM_SLOTS * SECTORS_PER_SLOT + NUM_REC_SECTORS; // 18
/// 器件总大小
pub const FLASH_SIZE: usize = TOTAL_SECTORS * SECTOR_SIZE; // 73728

/// 槽 0 起始偏移
pub const SLOT0_BASE: usize = 0;
/// 槽 1 起始偏移
pub const SLOT1_BASE: usize = SLOT_SIZE;
/// 记录区起始偏移
pub const REC_BASE: usize = NUM_SLOTS * SLOT_SIZE;

/// 发布记录定长：104 字节
pub const REC_SIZE: usize = 104;
/// 记录本体（参与哈希的部分）长度：64 字节
pub const REC_BODY_LEN: usize = 64;
/// 每个记录扇区可容纳的记录数（120 字节头部之后 38 条）
pub const RECORDS_PER_SECTOR: usize = (SECTOR_SIZE - REC_SECT_HEADER_LEN) / REC_SIZE; // 38

/// 记录魔数
pub const REC_MAGIC: [u8; 8] = *b"FWREC\0\0\0";
// 记录内偏移：
const REC_OFF_MAGIC: usize = 0; // 8 字节
const REC_OFF_SEQ: usize = 8; // 8 字节，u64 大端
const REC_OFF_SLOT: usize = 16; // 1 字节
const REC_OFF_VERSION: usize = 17; // 4 字节，u32 大端
const REC_OFF_LEN: usize = 21; // 4 字节，u32 大端
// 25..32：保留位，保持 0xFF
const REC_OFF_FWHASH: usize = 32; // 32 字节（到 64）
const REC_OFF_BODYHASH: usize = 64; // 32 字节（到 96）
const REC_OFF_COMMIT: usize = 96; // 8 字节（到 104）
/// 记录 commit 魔数（8 字节，整个记录最后编程）
pub const REC_COMMIT_MAGIC: [u8; 8] = *b"REC-CMMT";

/// 记录扇区头长度：120 字节
pub const REC_SECT_HEADER_LEN: usize = 120;
const HDR_OFF_MAGIC: usize = 0; // 8
const HDR_OFF_GEN: usize = 8; // 8
const HDR_OFF_COMMIT: usize = 16; // 16
/// 扇区头魔数（8 字节）
pub const HDR_MAGIC: [u8; 8] = *b"RECAREA!";
/// 扇区头 commit 魔数（16 字节，扇区激活的最后一步）
pub const HDR_COMMIT_MAGIC: [u8; 16] = *b"SECTOR-COMMIT!!\0";

/// 一条已编码记录的字段（换代号来自所在扇区头）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecFields {
    pub seq: u64,
    pub slot: u8,
    pub version: u32,
    pub data_len: u32,
    pub fw_hash: [u8; 32],
}

/// 记录在器件中的绝对位置
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecAddr {
    /// 记录区扇区号（0 或 1）
    pub rs: usize,
    /// 扇区内记录下标（0..RECORDS_PER_SECTOR）
    pub idx: usize,
}

impl RecAddr {
    pub fn new(rs: usize, idx: usize) -> Self {
        assert!(rs < NUM_REC_SECTORS && idx < RECORDS_PER_SECTOR);
        RecAddr { rs, idx }
    }
    /// 记录起始的绝对偏移
    pub fn offset(&self) -> usize {
        REC_BASE + self.rs * SECTOR_SIZE + REC_SECT_HEADER_LEN + self.idx * REC_SIZE
    }
}

/// 记录扇区头的绝对偏移
pub fn sector_header_offset(rs: usize) -> usize {
    REC_BASE + rs * SECTOR_SIZE
}

fn put_u64(buf: &mut [u8], v: u64) {
    buf[..8].copy_from_slice(&v.to_be_bytes());
}
fn put_u32(buf: &mut [u8], v: u32) {
    buf[..4].copy_from_slice(&v.to_be_bytes());
}
fn get_u64(buf: &[u8]) -> u64 {
    u64::from_be_bytes(buf[..8].try_into().unwrap())
}
fn get_u32(buf: &[u8]) -> u32 {
    u32::from_be_bytes(buf[..4].try_into().unwrap())
}

/// 生成记录的 104 字节镜像（擦除态全 0xFF，只有相关位被写成 0）。
/// commit 魔数也一并给出，调用方负责把它安排在最后编程。
pub fn encode_record(f: &RecFields) -> [u8; REC_SIZE] {
    let mut buf = [0xFFu8; REC_SIZE];
    buf[REC_OFF_MAGIC..REC_OFF_MAGIC + 8].copy_from_slice(&REC_MAGIC);
    put_u64(&mut buf[REC_OFF_SEQ..], f.seq);
    buf[REC_OFF_SLOT] = f.slot;
    put_u32(&mut buf[REC_OFF_VERSION..], f.version);
    put_u32(&mut buf[REC_OFF_LEN..], f.data_len);
    buf[REC_OFF_FWHASH..REC_OFF_FWHASH + 32].copy_from_slice(&f.fw_hash);
    // 本体 SHA-256（本体为 0..64）
    let body_hash = crate::sha256::sha256(&buf[..REC_BODY_LEN]);
    buf[REC_OFF_BODYHASH..REC_OFF_BODYHASH + 32].copy_from_slice(&body_hash);
    buf[REC_OFF_COMMIT..REC_OFF_COMMIT + 8].copy_from_slice(&REC_COMMIT_MAGIC);
    buf
}

/// 记录扇区头的 120 字节镜像（commit 魔数也给出，激活时最后编程）。
pub fn encode_sector_header(generation: u64) -> [u8; REC_SECT_HEADER_LEN] {
    let mut buf = [0xFFu8; REC_SECT_HEADER_LEN];
    buf[HDR_OFF_MAGIC..HDR_OFF_MAGIC + 8].copy_from_slice(&HDR_MAGIC);
    put_u64(&mut buf[HDR_OFF_GEN..], generation);
    buf[HDR_OFF_COMMIT..HDR_OFF_COMMIT + 16].copy_from_slice(&HDR_COMMIT_MAGIC);
    buf
}

/// 记录的校验结果
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecKind {
    /// 已完整提交：commit 魔数完整、本体哈希正确、魔数/槽号合法
    Committed(RecFields),
    /// 整个槽位仍是擦除态（0xFF）
    Empty,
    /// 有 0 位但未构成完整提交（写入被掉电撕碎，或部分擦除残留）
    Torn,
}

/// 检查某个绝对地址处的记录
pub fn classify_record(flash: &[u8], addr: RecAddr) -> RecKind {
    let off = addr.offset();
    let raw = &flash[off..off + REC_SIZE];
    if raw.iter().all(|&b| b == 0xFF) {
        return RecKind::Empty;
    }
    let commit_ok = raw[REC_OFF_COMMIT..REC_OFF_COMMIT + 8] == REC_COMMIT_MAGIC;
    let body_hash = crate::sha256::sha256(&raw[..REC_BODY_LEN]);
    let body_ok = body_hash == raw[REC_OFF_BODYHASH..REC_OFF_BODYHASH + 32];
    let magic_ok = raw[REC_OFF_MAGIC..REC_OFF_MAGIC + 8] == REC_MAGIC;
    if commit_ok && body_ok && magic_ok {
        let slot = raw[REC_OFF_SLOT];
        if (slot as usize) < NUM_SLOTS {
            return RecKind::Committed(RecFields {
                seq: get_u64(&raw[REC_OFF_SEQ..]),
                slot,
                version: get_u32(&raw[REC_OFF_VERSION..]),
                data_len: get_u32(&raw[REC_OFF_LEN..]),
                fw_hash: raw[REC_OFF_FWHASH..REC_OFF_FWHASH + 32]
                    .try_into()
                    .unwrap(),
            });
        }
    }
    RecKind::Torn
}

/// 记录扇区头的状态
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderKind {
    /// 完全擦除
    Blank,
    /// 已激活（魔数 + commit 都在），携带换代号
    Active(u64),
    /// 头部写了一半（或被部分擦除）
    Torn,
}

/// 检查记录区扇区头
pub fn classify_header(flash: &[u8], rs: usize) -> HeaderKind {
    let off = sector_header_offset(rs);
    let raw = &flash[off..off + REC_SECT_HEADER_LEN];
    if raw.iter().all(|&b| b == 0xFF) {
        return HeaderKind::Blank;
    }
    let magic_ok = raw[HDR_OFF_MAGIC..HDR_OFF_MAGIC + 8] == HDR_MAGIC;
    let commit_ok = raw[HDR_OFF_COMMIT..HDR_OFF_COMMIT + 16] == HDR_COMMIT_MAGIC;
    if magic_ok && commit_ok {
        HeaderKind::Active(get_u64(&raw[HDR_OFF_GEN..]))
    } else {
        HeaderKind::Torn
    }
}

/// 槽编号 -> 固件数据起始偏移
pub fn slot_base(slot: u8) -> usize {
    match slot {
        0 => SLOT0_BASE,
        1 => SLOT1_BASE,
        _ => panic!("bad slot {slot}"),
    }
}
