//! 启动检查：只读闪存记录，判定最新的完整固件。
//!
//! 启动器不依赖任何内存状态。判定步骤：
//! 1. 只承认「扇区头已激活」的记录扇区（换代写到一半的扇区整个忽略）；
//! 2. 在其中逐条检查发布记录，commit 魔数 + 本体 SHA-256 缺一不可，
//!    掉电撕碎的半包记录直接跳过；
//! 3. 完整记录按 (换代号, 记录序号) 取最新；
//! 4. 还要对槽内固件数据做 SHA-256 校验——记录指向的数据损坏
//!    （如部分擦除残留）时回退到次新记录，绝不使用半包。

use crate::flash::Flash;
use crate::layout::{
    classify_header, classify_record, slot_base, HeaderKind, RecAddr, RecFields, RECORDS_PER_SECTOR,
    NUM_REC_SECTORS, NUM_SLOTS,
};
use crate::sha256::sha256;

/// 一条通过了结构校验的完整发布记录
#[derive(Debug, Clone)]
pub struct Committed {
    pub fields: RecFields,
    pub generation: u64,
    pub addr: RecAddr,
}

/// 被跳过记录的审计信息
#[derive(Debug, Clone)]
pub struct Skipped {
    pub addr: RecAddr,
    pub why: &'static str,
}

/// 一次启动检查的完整报告
#[derive(Debug, Clone)]
pub struct BootReport {
    /// 最终选择（None = 没有可启动固件）
    pub chosen: Option<Chosen>,
    /// 所有结构完整的发布记录（新 -> 旧）
    pub candidates: Vec<Committed>,
    /// 被跳过的损坏/未完成记录
    pub skipped: Vec<Skipped>,
}

/// 最终选中的固件
#[derive(Debug, Clone)]
pub struct Chosen {
    pub slot: u8,
    pub version: u32,
    pub seq: u64,
    pub generation: u64,
    pub data_len: u32,
    pub addr: RecAddr,
}

/// 校验槽内固件数据是否与记录声明一致。
/// 长度按声明读取（未使用的尾页字节应仍为 0xFF），只哈希 data_len 个字节。
pub fn verify_firmware(flash: &Flash, c: &Committed) -> bool {
    let f = &c.fields;
    let len = f.data_len as usize;
    if len == 0 || len > crate::layout::SLOT_SIZE {
        return false;
    }
    let base = slot_base(f.slot);
    let data = flash.read(base, len);
    sha256(data) == f.fw_hash
}

/// 执行启动检查（纯只读）
pub fn inspect(flash: &Flash) -> BootReport {
    let mut candidates: Vec<Committed> = Vec::new();
    let mut skipped: Vec<Skipped> = Vec::new();

    for rs in 0..NUM_REC_SECTORS {
        // 头部未激活（空白或撕碎）的扇区，其中任何内容都不承认
        let generation = match classify_header(flash.image(), rs) {
            HeaderKind::Active(g) => g,
            HeaderKind::Blank => continue,
            HeaderKind::Torn => continue,
        };
        for idx in 0..RECORDS_PER_SECTOR {
            let addr = RecAddr::new(rs, idx);
            match classify_record(flash.image(), addr) {
                crate::layout::RecKind::Committed(fields) => {
                    candidates.push(Committed { fields, generation, addr });
                }
                crate::layout::RecKind::Empty => {}
                crate::layout::RecKind::Torn => {
                    skipped.push(Skipped {
                        addr,
                        why: "记录未完整提交（commit 魔数或本体哈希不符，疑似掉电半包）",
                    });
                }
            }
        }
    }

    // 新 -> 旧：先比换代号，再比记录内单调序号
    candidates.sort_by(|a, b| {
        b.generation
            .cmp(&a.generation)
            .then(b.fields.seq.cmp(&a.fields.seq))
    });

    let mut chosen = None;
    let mut survivors = Vec::with_capacity(candidates.len());
    for c in candidates {
        let fw_ok = verify_firmware(flash, &c);
        if chosen.is_none() && fw_ok {
            chosen = Some(Chosen {
                slot: c.fields.slot,
                version: c.fields.version,
                seq: c.fields.seq,
                generation: c.generation,
                data_len: c.fields.data_len,
                addr: c.addr,
            });
        } else if !fw_ok && chosen.is_none() {
            skipped.push(Skipped {
                addr: c.addr,
                why: "记录完整但其指向的固件数据 SHA-256 不符（数据区损坏）",
            });
        }
        survivors.push(c);
    }

    BootReport {
        chosen,
        candidates: survivors,
        skipped,
    }
}

/// 选择依据的人类可读描述
pub fn reason_text(r: &BootReport) -> String {
    match &r.chosen {
        Some(c) => format!(
            "记录区换代号 {}、序号 {} 为最新完整发布记录（槽 {}，版本 v{}，{} 字节），固件 SHA-256 校验通过",
            c.generation, c.seq, c.slot, c.version, c.data_len
        ),
        None => "记录区中没有指向完好固件的完整发布记录（无有效启动镜像）".to_string(),
    }
}

/// 供更新器使用：当前活动扇区摘要
#[derive(Debug, Clone)]
pub struct SectorView {
    pub rs: usize,
    pub generation: u64,
    pub committed: Vec<Committed>,
    /// 可安全追加的下标：最后一个非空（完整或撕碎）记录的紧后槽位；
    /// 为 None 表示扇区没有任何已占用记录（从 idx0 开始）。
    /// 注意不是「第一个空槽」：撕碎槽位虽然非空但不可写，
    /// 只能在其之后追加，否则会对 0 位编程而冲突。
    pub append_idx: Option<usize>,
    /// 扇区是否已写满（无可追加位置）
    pub full: bool,
    /// 扫描到的撕碎记录数
    pub torn: usize,
}

/// 扫描所有头部已激活的记录扇区
pub fn scan_active_sectors(flash: &Flash) -> Vec<SectorView> {
    let mut out = Vec::new();
    for rs in 0..NUM_REC_SECTORS {
        let generation = match classify_header(flash.image(), rs) {
            HeaderKind::Active(g) => g,
            _ => continue,
        };
        let mut committed = Vec::new();
        let mut last_used: Option<usize> = None;
        let mut torn = 0;
        for idx in 0..RECORDS_PER_SECTOR {
            let addr = RecAddr::new(rs, idx);
            match classify_record(flash.image(), addr) {
                crate::layout::RecKind::Committed(fields) => {
                    committed.push(Committed { fields, generation, addr });
                    last_used = Some(idx);
                }
                crate::layout::RecKind::Empty => {}
                crate::layout::RecKind::Torn => {
                    torn += 1;
                    // 撕碎槽位已占用但无效：记录追加必须越过它
                    last_used = Some(idx);
                }
            }
        }
        let next = last_used.map(|i| i + 1);
        let full = next == Some(RECORDS_PER_SECTOR);
        let append_idx = if full { None } else { next };
        out.push(SectorView {
            rs,
            generation,
            committed,
            append_idx,
            full,
            torn,
        });
    }
    out
}

/// 任意完整记录中的最大槽号（工厂/测试辅助）
#[allow(dead_code)]
pub fn any_committed_slot(flash: &Flash) -> Option<u8> {
    let r = inspect(flash);
    r.chosen.map(|c| c.slot)
}

/// 仅用于消除未使用告警
#[allow(dead_code)]
fn _used(_: usize) {
    let _ = NUM_SLOTS;
}
