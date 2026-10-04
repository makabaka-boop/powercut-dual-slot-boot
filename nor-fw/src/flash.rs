//! NOR 闪存模型与掉电故障夹具。
//!
//! 模型严格遵守 NOR 语义：
//! - 擦除后整扇区为 0xFF
//! - 编程只能把位 1 -> 0（尝试 0 -> 1 会报错，模拟真实硬件的位污染）
//! - 页写 `program_page` 每次 256 字节
//!
//! 夹具 [`Fixture`] 按「操作序号」在任意变异点之后切断电源：
//! 固件页的每个字节、发布记录/扇区头的每个字节、每次擦除都有独立序号。
//! 擦除中断不把扇区置为 0xFF，而是留下夹具指定的「部分擦除」图案。

use crate::layout::{
    sector_header_offset, FLASH_SIZE, PAGE_SIZE, REC_BASE, SECTOR_SIZE, TOTAL_SECTORS,
};

/// NOR 操作错误
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NorError {
    /// 尝试把 0 位编程成 1（真实 NOR 会产生错误位）
    ProgramConflict { offset: usize, old: u8, new: u8 },
    /// 越界访问
    OutOfRange(usize),
    /// 在该变异点掉电
    PowerCut,
    /// 更新请求被预检拒绝（版本不递增/过大/无当前固件等），闪存未改动
    Rejected(String),
}

impl std::fmt::Display for NorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NorError::ProgramConflict { offset, old, new } => write!(
                f,
                "编程冲突 @{offset:#x}: 试图把 {old:#04x} 写成 {new:#04x}（只允许 1->0）"
            ),
            NorError::OutOfRange(o) => write!(f, "越界访问 @{o:#x}"),
            NorError::PowerCut => write!(f, "掉电"),
            NorError::Rejected(s) => write!(f, "更新被拒绝：{s}"),
        }
    }
}
impl std::error::Error for NorError {}

/// 擦除中断后留下的部分擦除图案
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErasePattern {
    /// 正常擦除（不掉电）
    Clean,
    /// 全 0x00（擦除几乎没开始/被旧的编程态覆盖）
    AllZero,
    /// 前半 0x00 后半 0xFF
    KeepHead,
    /// 前半 0xFF 后半 0x00
    KeepTail,
    /// 棋盘格
    Checker,
    /// 每 16 字节保留一组旧数据（近似「条状未擦除」）
    Stripes,
}

impl ErasePattern {
    pub fn parse(s: &str) -> Option<ErasePattern> {
        Some(match s {
            "clean" => ErasePattern::Clean,
            "zero" => ErasePattern::AllZero,
            "keep-head" => ErasePattern::KeepHead,
            "keep-tail" => ErasePattern::KeepTail,
            "checker" => ErasePattern::Checker,
            "stripes" => ErasePattern::Stripes,
            _ => return None,
        })
    }
}

fn apply_pattern(buf: &mut [u8], pat: ErasePattern) {
    debug_assert_eq!(buf.len(), SECTOR_SIZE);
    match pat {
        ErasePattern::Clean => {
            buf.fill(0xFF);
        }
        ErasePattern::AllZero => buf.fill(0x00),
        ErasePattern::KeepHead => {
            buf.fill(0xFF);
            buf[..SECTOR_SIZE / 2].fill(0x00);
        }
        ErasePattern::KeepTail => {
            buf.fill(0xFF);
            buf[SECTOR_SIZE / 2..].fill(0x00);
        }
        ErasePattern::Checker => {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = if (i / 8 + i / 256) % 2 == 0 { 0x00 } else { 0xFF };
            }
        }
        ErasePattern::Stripes => {
            buf.fill(0xFF);
            for chunk in buf.chunks_mut(32) {
                chunk[..16].fill(0x00);
            }
        }
    }
}

/// 变异发生在更新流程的哪个阶段（供夹具分类与报告使用）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// 擦除目标固件槽的扇区（8 次）
    EraseSlot,
    /// 编程固件数据页
    ProgramData,
    /// 换代：擦除新记录扇区
    RolloverErase,
    /// 换代：写新扇区头（120 字节）
    RolloverHeader,
    /// 换代：搬运上一代最后一条完整记录（104 字节）
    RolloverCarry,
    /// 写本次发布记录（104 字节）
    WriteRecord,
    /// 换代完成后擦除旧记录扇区
    ReconcileErase,
}

/// 夹具选择的切点
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cut {
    /// 不掉电
    None,
    /// 第 n 次擦除（1 起）后掉电；使用指定部分擦除图案
    Erase { ordinal: u64, pattern: ErasePattern },
    /// 第 n 个固件页内的第 b 个字节（均 1 起，含填充字节）编程后掉电
    PageByte { page: u64, byte_in_page: u64 },
    /// 指定阶段内第 n 个被编程字节（1 起）后掉电
    /// （头 120 字节 / carry 104 字节 / 新记录 104 字节）
    RecordByte { phase: Phase, ordinal: u64 },
}

/// 掉电故障夹具
#[derive(Clone)]
pub struct Fixture {
    cut: Cut,
    // 各维度计数器（全部从 1 起）
    erase_no: u64,
    page_no: u64,
    byte_in_page: u64,
    phase_byte_no: u64,
    /// 最近一次操作的人类可读标签（掉电时报告）
    pub last_label: String,
}

impl Default for Fixture {
    fn default() -> Self {
        Fixture {
            cut: Cut::None,
            erase_no: 0,
            page_no: 0,
            byte_in_page: 0,
            phase_byte_no: 0,
            last_label: String::new(),
        }
    }
}

impl Fixture {
    pub fn new(cut: Cut) -> Self {
        Fixture {
            cut,
            ..Fixture::default()
        }
    }

    /// 进入新阶段时复位「阶段内字节」计数
    pub fn enter_phase(&mut self, phase: Phase) {
        self.phase_byte_no = 0;
        let _ = phase;
    }

    /// 一次擦除变异（扇区擦除本身算一个变异点）。
    /// 返回 true 表示此刻应当掉电，扇区内容为部分擦除图案。
    pub fn tick_erase(&mut self, global_sector: usize, pattern_for_cut: ErasePattern) -> Option<ErasePattern> {
        self.erase_no += 1;
        self.last_label = format!("擦除扇区 #{global_sector}（第 {} 次擦除）", self.erase_no);
        if let Cut::Erase { ordinal, pattern } = self.cut {
            if ordinal == self.erase_no {
                // CLI 指定的图案优先；未指定具体内容时用本次调用给出的图案
                let _ = pattern_for_cut;
                return Some(pattern);
            }
        }
        None
    }

    /// 一次「写字节」变异（记录头 / carry / 发布记录路径）。
    /// 返回 true 表示该字节落地后掉电。
    pub fn tick_record_byte(&mut self, phase: Phase, off_in_item: usize) -> bool {
        self.phase_byte_no += 1;
        self.last_label = format!(
            "{phase:?} 阶段第 {} 字节（项内偏移 {off_in_item}）",
            self.phase_byte_no
        );
        matches!(self.cut,
            Cut::RecordByte { phase: p, ordinal }
            if p == phase && ordinal == self.phase_byte_no)
    }

    /// 固件页内一个字节变异。`page` 为本次更新中的页序号（1 起）。
    pub fn tick_data_byte(&mut self, page: usize, byte_in_page: usize) -> bool {
        self.page_no = page as u64;
        self.byte_in_page = (byte_in_page + 1) as u64;
        self.last_label = format!(
            "本次更新第 {page} 个固件页第 {} 字节",
            byte_in_page + 1
        );
        matches!(self.cut, Cut::PageByte { page: p, byte_in_page: b }
            if p == self.page_no && b == (byte_in_page as u64 + 1))
    }
}

/// NOR 闪存模型
pub struct Flash {
    data: Vec<u8>,
}

impl Flash {
    /// 全新器件：全 0xFF（出厂擦除态）
    pub fn blank() -> Self {
        Flash {
            data: vec![0xFF; FLASH_SIZE],
        }
    }

    /// 从镜像载入（重开模拟器）
    pub fn from_image(img: &[u8]) -> Self {
        assert_eq!(img.len(), FLASH_SIZE, "镜像大小不符");
        Flash {
            data: img.to_vec(),
        }
    }

    pub fn image(&self) -> &[u8] {
        &self.data
    }

    pub fn read(&self, offset: usize, len: usize) -> &[u8] {
        &self.data[offset..offset + len]
    }

    pub fn byte_at(&self, offset: usize) -> u8 {
        self.data[offset]
    }

    /// 无夹具的原始字节编程：只允许 1 -> 0
    pub fn program_byte_raw(&mut self, offset: usize, val: u8) -> Result<(), NorError> {
        if offset >= self.data.len() {
            return Err(NorError::OutOfRange(offset));
        }
        let old = self.data[offset];
        if old & val != val {
            return Err(NorError::ProgramConflict {
                offset,
                old,
                new: val,
            });
        }
        self.data[offset] = old & val;
        Ok(())
    }

    /// 原始字节序列编程（不带掉电注入）
    pub fn program_bytes_raw(&mut self, offset: usize, bytes: &[u8]) -> Result<(), NorError> {
        for (i, &b) in bytes.iter().enumerate() {
            self.program_byte_raw(offset + i, b)?;
        }
        Ok(())
    }

    /// 原始扇区擦除
    pub fn erase_sector_raw(&mut self, global_sector: usize) -> Result<(), NorError> {
        let start = global_sector * SECTOR_SIZE;
        if start >= self.data.len() {
            return Err(NorError::OutOfRange(start));
        }
        self.data[start..start + SECTOR_SIZE].fill(0xFF);
        Ok(())
    }

    /// 带夹具的扇区擦除。若切点命中，留下部分擦除图案并返回 `PowerCut`。
    pub fn erase_sector(
        &mut self,
        global_sector: usize,
        fx: &mut Fixture,
        cut_pattern: ErasePattern,
    ) -> Result<(), NorError> {
        let start = global_sector * SECTOR_SIZE;
        if start >= self.data.len() {
            return Err(NorError::OutOfRange(start));
        }
        if let Some(pat) = fx.tick_erase(global_sector, cut_pattern) {
            // 擦除中断：扇区既不是干净擦除态，也不是旧内容，而是夹具指定图案
            apply_pattern(&mut self.data[start..start + SECTOR_SIZE], pat);
            return Err(NorError::PowerCut);
        }
        self.data[start..start + SECTOR_SIZE].fill(0xFF);
        Ok(())
    }

    /// 带夹具的字节编程（记录路径）。字节落地后若切点命中则掉电。
    pub fn program_record_item(
        &mut self,
        offset: usize,
        item: &[u8],
        phase: Phase,
        fx: &mut Fixture,
    ) -> Result<(), NorError> {
        fx.enter_phase(phase);
        for (i, &b) in item.iter().enumerate() {
            self.program_byte_raw(offset + i, b)?;
            if fx.tick_record_byte(phase, i) {
                return Err(NorError::PowerCut);
            }
        }
        Ok(())
    }

    /// 带夹具的固件页编程：页内每个字节都是掉电点。
    /// - `flash_page`：该页在器件中的绝对页号（决定编程地址）
    /// - `ordinal`：本次更新中的页序号（1 起，决定夹具切点与报告文案）
    /// `page_data` 长度必须为 256（最后一页由调用方以 0xFF 填充）。
    pub fn program_firmware_page(
        &mut self,
        flash_page: usize,
        ordinal: usize,
        page_data: &[u8],
        fx: &mut Fixture,
    ) -> Result<(), NorError> {
        assert_eq!(page_data.len(), PAGE_SIZE);
        let base = flash_page * PAGE_SIZE;
        for (i, &b) in page_data.iter().enumerate() {
            self.program_byte_raw(base + i, b)?;
            if fx.tick_data_byte(ordinal, i) {
                return Err(NorError::PowerCut);
            }
        }
        Ok(())
    }

    /// 全局扇区号 -> 该扇区属于哪个区域的标签
    pub fn sector_label(global_sector: usize) -> &'static str {
        if global_sector < 8 {
            "槽0"
        } else if global_sector < 16 {
            "槽1"
        } else {
            "记录区"
        }
    }

    /// 记录区扇区号 -> 全局扇区号
    pub fn rec_sector_global(rs: usize) -> usize {
        let _ = REC_BASE;
        TOTAL_SECTORS - 2 + rs
    }

    /// 记录扇区头全局偏移（便捷接口）
    pub fn rec_header_offset(rs: usize) -> usize {
        sector_header_offset(rs)
    }
}
