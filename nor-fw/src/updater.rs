//! 更新器：只能擦写「非当前槽」，完整写入并逐字节读回核验后才发布。
//!
//! 发布（追加路径）：在当前记录扇区的下一个空槽写 104 字节记录，
//! commit 魔数位于字节 96..104，因此记录必然「先数据后提交」。
//!
//! 发布（换代路径）：当前扇区写满时——
//! 1. 擦除另一记录扇区，写入 generation+1 的新头（头 commit 最后写）；
//! 2. 把上一代「最后可启动版本」的记录原样搬运到新扇区 idx 0；
//! 3. 在 idx 1 写本次新记录；
//! 4. 两条记录都在新扇区落地后，才擦除旧扇区。
//! 任意一步掉电，旧扇区（或新扇区的 carry）至少保留一个完整可启动版本。

use crate::boot::{inspect, scan_active_sectors, BootReport, Committed};
use crate::flash::{Cut, ErasePattern, Fixture, Flash, NorError, Phase};
use crate::layout::{
    encode_record, encode_sector_header, slot_base, RecAddr, RecFields, NUM_REC_SECTORS,
    PAGE_SIZE, RECORDS_PER_SECTOR, SECTORS_PER_SLOT, SLOT_SIZE,
};
use crate::package::Package;
use crate::sha256::sha256;

/// 更新结果
#[derive(Debug, Clone)]
pub struct UpdateOutcome {
    pub slot: u8,
    pub version: u32,
    pub seq: u64,
    pub generation: u64,
    pub rolled_over: bool,
}

/// 更新前的检查
pub fn precheck(flash: &Flash, pkg: &Package) -> Result<BootReport, String> {
    let report = inspect(flash);
    let current = report
        .chosen
        .as_ref()
        .ok_or("当前没有可启动固件，拒绝在未知状态下更新")?;
    if pkg.version <= current.version {
        return Err(format!(
            "版本必须递增：当前 v{}，包为 v{}",
            current.version, pkg.version
        ));
    }
    if pkg.data.len() > SLOT_SIZE {
        return Err(format!(
            "固件过大：{} 字节，槽容量 {SLOT_SIZE}",
            pkg.data.len()
        ));
    }
    if sha256(&pkg.data) != pkg.hash {
        return Err("更新包载荷 SHA-256 与包内记录不符".to_string());
    }
    Ok(report)
}

/// 执行一次更新。掉电以 `Err(NorError::PowerCut)` 返回，闪存内容保留断点状态。
pub fn run_update(
    flash: &mut Flash,
    pkg: &Package,
    fx: &mut Fixture,
) -> Result<UpdateOutcome, NorError> {
    let report = precheck(flash, pkg).map_err(NorError::Rejected)?;
    let current = report.chosen.as_ref().expect("precheck 保证存在");
    let target_slot: u8 = 1 - current.slot; // 只能擦写非当前槽
    let target_base = slot_base(target_slot);
    let slot_first_sector = (target_slot as usize) * SECTORS_PER_SLOT;

    // ---- 1) 擦除非当前槽的 8 个扇区 ----
    fx.enter_phase(Phase::EraseSlot);
    for k in 0..SECTORS_PER_SLOT {
        flash.erase_sector(slot_first_sector + k, fx, ErasePattern::Clean)?;
    }

    // ---- 2) 按 256 字节页写入（最后一页以 0xFF 填充）----
    let mut padded = pkg.data.clone();
    while padded.len() % PAGE_SIZE != 0 {
        padded.push(0xFF);
    }
    fx.enter_phase(Phase::ProgramData);
    for (p, chunk) in padded.chunks_exact(PAGE_SIZE).enumerate() {
        flash.program_firmware_page(target_base / PAGE_SIZE + p, p + 1, chunk, fx)?;
    }

    // ---- 3) 逐字节读回核验：载荷 + 尾页填充 + 槽内其余空间 ----
    let written = flash.read(target_base, padded.len());
    if written != padded.as_slice() {
        // 正常 NOR 模型不会走到这里；属于防御性检查
        return Err(NorError::ProgramConflict {
            offset: target_base,
            old: 0,
            new: 0,
        });
    }
    let tail_base = target_base + padded.len();
    let tail_len = SLOT_SIZE - padded.len();
    if tail_len > 0 && !flash.read(tail_base, tail_len).iter().all(|&b| b == 0xFF) {
        return Err(NorError::ProgramConflict {
            offset: tail_base,
            old: 0,
            new: 0,
        });
    }
    let fw_hash = sha256(&pkg.data);

    // ---- 4) 决定发布位置 ----
    let sectors = scan_active_sectors(flash);
    let max_seq = sectors
        .iter()
        .flat_map(|s| s.committed.iter().map(|c| c.fields.seq))
        .max()
        .unwrap_or(0);
    let new_seq = max_seq + 1;

    let newest = sectors.iter().max_by_key(|s| s.generation);
    let can_append = newest.map(|s| s.append_idx.is_some()).unwrap_or(false);

    let (generation, rolled_over) = if can_append {
        let s = newest.unwrap();
        let idx = s.append_idx.unwrap();
        let rec = RecFields {
            seq: new_seq,
            slot: target_slot,
            version: pkg.version,
            data_len: pkg.data.len() as u32,
            fw_hash,
        };
        publish_record(flash, s.rs, idx, &rec, Phase::WriteRecord, fx)?;
        // 若历史遗留了另一个活动扇区，新记录落地后再回收它
        for other in &sectors {
            if other.rs != s.rs {
                flash.erase_sector(
                    crate::flash::Flash::rec_sector_global(other.rs),
                    fx,
                    ErasePattern::Clean,
                )?;
            }
        }
        (s.generation, false)
    } else {
        rollover_and_publish(flash, &sectors, target_slot, pkg, fw_hash, new_seq, fx)?
    };

    Ok(UpdateOutcome {
        slot: target_slot,
        version: pkg.version,
        seq: new_seq,
        generation,
        rolled_over,
    })
}

/// 在指定记录槽位写入记录（104 字节顺序编程，commit 魔数在最后 8 字节）
fn publish_record(
    flash: &mut Flash,
    rs: usize,
    idx: usize,
    fields: &RecFields,
    phase: Phase,
    fx: &mut Fixture,
) -> Result<(), NorError> {
    let addr = RecAddr::new(rs, idx);
    let buf = encode_record(fields);
    flash.program_record_item(addr.offset(), &buf, phase, fx)
}

/// 换代发布：返回 (新换代号, true)
fn rollover_and_publish(
    flash: &mut Flash,
    sectors: &[crate::boot::SectorView],
    target_slot: u8,
    pkg: &Package,
    fw_hash: [u8; 32],
    new_seq: u64,
    fx: &mut Fixture,
) -> Result<(u64, bool), NorError> {
    let old = sectors.iter().max_by_key(|s| s.generation);
    let new_gen = old.map(|s| s.generation + 1).unwrap_or(1);
    let old_rs = old.map(|s| s.rs);

    // 新扇区 = 不是旧活动扇区的那个（头部是 Blank 还是 Torn 都直接整片擦除）
    let new_rs = match old_rs {
        Some(r) => 1 - r,
        None => 0,
    };
    debug_assert!(new_rs < NUM_REC_SECTORS);

    // 1) 擦除新扇区
    fx.enter_phase(Phase::RolloverErase);
    flash.erase_sector(
        Flash::rec_sector_global(new_rs),
        fx,
        ErasePattern::Clean,
    )?;

    // 2) 写新扇区头：只有 32 个有效字节（魔数 8 + generation 8 + commit 16）
    fx.enter_phase(Phase::RolloverHeader);
    let hdr = encode_sector_header(new_gen);
    flash.program_record_item(
        Flash::rec_header_offset(new_rs),
        &hdr[..32],
        Phase::RolloverHeader,
        fx,
    )?;

    // 3) 搬运上一代最新完整记录（保护最后可启动版本）
    let carry: Option<Committed> = old.and_then(|s| {
        s.committed
            .iter()
            .max_by_key(|c| c.fields.seq)
            .cloned()
    });
    if let Some(c) = &carry {
        let mut fields = c.fields.clone();
        // 搬运记录保持原 seq；它与新记录同处新 generation，顺序不变
        let _ = &mut fields;
        publish_record(flash, new_rs, 0, &c.fields, Phase::RolloverCarry, fx)?;
    }

    // 4) 写本次新记录（carry 占了 idx 0；无 carry 时写 idx 0）
    let new_idx = if carry.is_some() { 1 } else { 0 };
    let rec = RecFields {
        seq: new_seq,
        slot: target_slot,
        version: pkg.version,
        data_len: pkg.data.len() as u32,
        fw_hash,
    };
    publish_record(flash, new_rs, new_idx, &rec, Phase::WriteRecord, fx)?;

    // 5) 新旧版本都已在新扇区落地，才擦除旧扇区
    if let Some(r) = old_rs {
        fx.enter_phase(Phase::ReconcileErase);
        flash.erase_sector(
            Flash::rec_sector_global(r),
            fx,
            ErasePattern::Clean,
        )?;
    }

    Ok((new_gen, true))
}

/// 工厂预置：整片擦除，槽 0 写固件，记录扇区 0 写头 + 首条发布记录。
/// 工厂流程不做故障注入（但使用同一套编程原语，保证记录格式一致）。
pub fn factory_provision(
    flash: &mut Flash,
    version: u32,
    data: &[u8],
) -> Result<UpdateOutcome, NorError> {
    for s in 0..crate::layout::TOTAL_SECTORS {
        flash.erase_sector_raw(s)?;
    }
    let mut padded = data.to_vec();
    while padded.len() % PAGE_SIZE != 0 {
        padded.push(0xFF);
    }
    let base = slot_base(0);
    flash.program_bytes_raw(base, &padded)?;

    let fw_hash = sha256(data);
    let hdr = encode_sector_header(1);
    flash.program_bytes_raw(Flash::rec_header_offset(0), &hdr[..32])?;
    let rec = RecFields {
        seq: 1,
        slot: 0,
        version,
        data_len: data.len() as u32,
        fw_hash,
    };
    let buf = encode_record(&rec);
    flash.program_bytes_raw(RecAddr::new(0, 0).offset(), &buf)?;

    Ok(UpdateOutcome {
        slot: 0,
        version,
        seq: 1,
        generation: 1,
        rolled_over: false,
    })
}

#[allow(dead_code)]
fn _assert_cuts(_: Cut) {
    let _ = RECORDS_PER_SECTOR;
}
