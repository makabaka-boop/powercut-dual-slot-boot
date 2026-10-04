//! 掉电复演：遍历小固件的全部切口与记录区换代。
//!
//! 每个试次都从相同基线复制一份内存闪存（模拟「断电前的快照」），
//! 在指定变异点掉电，随后重开电源检查启动选择；再用一份无故障的
//! 更新收尾，验证系统最终仍能到达新版本（活性）。

use crate::boot::inspect;
use crate::flash::{Cut, ErasePattern, Fixture, Flash, NorError, Phase};
use crate::package::Package;
use crate::updater;

/// 生成确定性测试固件（同版本、同长度永远一致；不同版本内容不同）
pub fn make_firmware(version: u32, len: usize) -> Vec<u8> {
    let mut state = version.wrapping_mul(2654435761) ^ 0x9E3779B9;
    let mut out = Vec::with_capacity(len);
    for i in 0..len {
        // 线性同余，掺上位置
        state = state.wrapping_mul(1103515245).wrapping_add(12345);
        out.push(((state >> 16) as u8) ^ (i as u8).wrapping_mul(31) ^ version as u8);
    }
    out
}

/// 小固件切口遍历所用的尺寸（覆盖页边界两侧）
pub const SWEEP_SIZES: &[usize] = &[1, 255, 256, 257, 511, 512, 513];

const PARTIAL_PATTERNS: [ErasePattern; 5] = [
    ErasePattern::AllZero,
    ErasePattern::KeepHead,
    ErasePattern::KeepTail,
    ErasePattern::Checker,
    ErasePattern::Stripes,
];

fn pattern_name(p: ErasePattern) -> &'static str {
    match p {
        ErasePattern::Clean => "clean",
        ErasePattern::AllZero => "zero",
        ErasePattern::KeepHead => "keep-head",
        ErasePattern::KeepTail => "keep-tail",
        ErasePattern::Checker => "checker",
        ErasePattern::Stripes => "stripes",
    }
}

/// 一个试次的结果
#[derive(Debug, Clone)]
pub struct TrialResult {
    pub cut: String,
    pub reboot_slot: u8,
    pub reboot_version: u32,
    pub reboot_reason: String,
    pub reached_version: u32,
    pub ok: bool,
    pub detail: String,
}

/// 一组试次的聚合统计
#[derive(Debug, Clone, Default)]
pub struct Summary {
    /// 重开后选中旧完整版本的试次数
    pub boot_old: usize,
    /// 重开后选中已完整发布新版本的试次数
    pub boot_new: usize,
    /// 无故障重试后到达新版本的试次数（活性）
    pub recovered: usize,
}

/// 对一批试次结果做聚合
pub fn summarize(results: &[TrialResult]) -> Summary {
    let mut s = Summary::default();
    for r in results {
        if !r.ok {
            continue;
        }
        if r.reboot_version < r.reached_version {
            s.boot_old += 1;
        } else {
            s.boot_new += 1;
        }
        // 所有通过的试次最终都到达了目标新版本
        s.recovered += 1;
    }
    s
}

/// 断言重开后选中的固件数据与版本对应
fn check_selected(flash: &Flash, expect_v1: u32, expect_v2: u32) -> Result<(u8, u32, String), String> {
    let r = inspect(flash);
    let c = r
        .chosen
        .as_ref()
        .ok_or("重开后没有任何可启动固件")?;
    if c.version != expect_v1 && c.version != expect_v2 {
        return Err(format!(
            "选中了意外版本 v{}（只允许 v{} 或 v{}）",
            c.version, expect_v1, expect_v2
        ));
    }
    // inspect 只对固件做过 SHA-256；这里按确定载荷逐字节复核
    let candidate = r
        .candidates
        .iter()
        .find(|x| x.fields.seq == c.seq && x.generation == c.generation)
        .unwrap();
    if !crate::boot::verify_firmware(flash, candidate) {
        return Err("所选固件 SHA-256 复核失败".into());
    }
    // 数据内容必须与该版本的确定性载荷一致
    let expect_payload = make_firmware(c.version, c.data_len as usize);
    let base = crate::layout::slot_base(c.slot);
    let actual = flash.read(base, c.data_len as usize);
    if actual != expect_payload.as_slice() {
        return Err(format!("槽 {} 的数据与版本 v{} 的期望载荷不符", c.slot, c.version));
    }
    Ok((c.slot, c.version, crate::boot::reason_text(&r)))
}

/// 跑单个切口试次。
/// - `base`：掉电前闪存快照
/// - `old_version`：更新前最新完整版本（掉电后允许选中旧完整版本）
/// - `pkg`：正在写入的新版本包
fn run_trial(
    base: &Flash,
    old_version: u32,
    pkg: &Package,
    cut: Cut,
    cut_name: String,
) -> TrialResult {
    let mut flash = Flash::from_image(base.image());
    let mut fx = Fixture::new(cut);
    let upd = updater::run_update(&mut flash, pkg, &mut fx);
    let cut_label = fx.last_label.clone();

    let mut detail = String::new();
    if let Err(NorError::PowerCut) = upd {
        detail = format!("掉电点：{cut_label}");
    } else if let Err(e) = upd {
        return TrialResult {
            cut: cut_name,
            reboot_slot: 0,
            reboot_version: 0,
            reboot_reason: String::new(),
            reached_version: 0,
            ok: false,
            detail: format!("更新异常终止：{e}"),
        };
    }

    // 重开电源：只读检查——必须选中旧完整版本或已完整发布的新版本
    let reboot = match check_selected(&flash, old_version, pkg.version) {
        Ok(v) => v,
        Err(e) => {
            return TrialResult {
                cut: cut_name,
                reboot_slot: 0,
                reboot_version: 0,
                reboot_reason: String::new(),
                reached_version: 0,
                ok: false,
                detail: format!("{detail}；{e}"),
            }
        }
    };

    // 活性收尾：若尚未发布新版本，用无故障更新走完
    let reached = if reboot.1 < pkg.version {
        let mut fx2 = Fixture::default();
        match updater::run_update(&mut flash, pkg, &mut fx2) {
            Ok(o) => o.version,
            Err(NorError::PowerCut) => unreachable!("无故障夹具不应掉电"),
            Err(e) => {
                return TrialResult {
                    cut: cut_name,
                    reboot_slot: reboot.0,
                    reboot_version: reboot.1,
                    reboot_reason: reboot.2,
                    reached_version: 0,
                    ok: false,
                    detail: format!("{detail}；收尾更新失败：{e}"),
                }
            }
        }
    } else {
        pkg.version
    };
    let final_ok = match check_selected(&flash, reached, reached) {
        Ok(_) => true,
        Err(e) => {
            return TrialResult {
                cut: cut_name,
                reboot_slot: reboot.0,
                reboot_version: reboot.1,
                reboot_reason: reboot.2,
                reached_version: reached,
                ok: false,
                detail: format!("{detail}；收尾后 {e}"),
            }
        }
    };

    TrialResult {
        cut: cut_name,
        reboot_slot: reboot.0,
        reboot_version: reboot.1,
        reboot_reason: reboot.2,
        reached_version: reached,
        ok: final_ok,
        detail,
    }
}

/// 小固件的全部切口遍历。返回全部试次结果。
pub fn sweep_small_firmware() -> Vec<TrialResult> {
    let mut results = Vec::new();

    for &size in SWEEP_SIZES {
        let seed = make_firmware(1, size);
        let mut base = Flash::blank();
        updater::factory_provision(&mut base, 1, &seed).expect("工厂预置失败");
        let pkg = Package::new(2, make_firmware(2, size));

        let pages = size.div_ceil(256);

        // 1) 每个固件页的每个字节后掉电
        for p in 1..=pages as u64 {
            for b in 1..=256u64 {
                let cut = Cut::PageByte {
                    page: p,
                    byte_in_page: b,
                };
                let name = format!("size={size} 固件页#{p}字节#{b}");
                results.push(run_trial(&base, 1, &pkg, cut, name));
            }
        }

        // 2) 发布记录逐字节（104 字节；最后 8 字节是 commit 魔数）
        for n in 1..=104u64 {
            let cut = Cut::RecordByte {
                phase: Phase::WriteRecord,
                ordinal: n,
            };
            let name = format!("size={size} 发布记录字节#{n}");
            results.push(run_trial(&base, 1, &pkg, cut, name));
        }

        // 3) 每次擦除后掉电（追加路径共 8 次：擦目标槽），遍历部分擦除图案
        for ord in 1..=8u64 {
            for pat in PARTIAL_PATTERNS {
                let cut = Cut::Erase {
                    ordinal: ord,
                    pattern: pat,
                };
                let name = format!("size={size} 擦除#{ord}:{}", pattern_name(pat));
                results.push(run_trial(&base, 1, &pkg, cut, name));
            }
        }
    }

    results
}

/// 把闪存推进到「刚写完 v{n}」的状态（无故障连续更新）
fn advance_to(base_version: u32, size: usize, target_version: u32) -> Flash {
    let seed = make_firmware(1, size);
    let mut flash = Flash::blank();
    updater::factory_provision(&mut flash, 1, &seed).unwrap();
    for v in (base_version + 1)..=target_version {
        let pkg = Package::new(v, make_firmware(v, size));
        let mut fx = Fixture::default();
        updater::run_update(&mut flash, &pkg, &mut fx).expect("无故障更新失败");
        let r = inspect(&flash);
        assert_eq!(r.chosen.as_ref().map(|c| c.version), Some(v));
    }
    flash
}

/// 换代点的全部切口遍历，并继续推进多代验证循环使用。返回全部试次结果。
pub fn sweep_rollover() -> Vec<TrialResult> {
    let size = 200usize; // 单页小固件，换代快
    let mut results = Vec::new();

    // 扇区容量 38 条：工厂 seq1 占 idx0，连续更新到 v38 写满，v39 触发换代
    let base = advance_to(1, size, 38);
    let pkg39 = Package::new(39, make_firmware(39, size));

    let push_cut = |cut: Cut, name: String, results: &mut Vec<TrialResult>| {
        results.push(run_trial(&base, 38, &pkg39, cut, name));
    };

    // 槽擦除 8 次 + 换代擦新扇区 1 次 + 回收旧扇区 1 次 = 10 次
    for ord in 1..=10u64 {
        for pat in PARTIAL_PATTERNS {
            push_cut(
                Cut::Erase {
                    ordinal: ord,
                    pattern: pat,
                },
                format!("换代更新 擦除#{ord}:{}", pattern_name(pat)),
                &mut results,
            );
        }
    }
    // 新扇区头 32 个有效字节
    for n in 1..=32u64 {
        push_cut(
            Cut::RecordByte {
                phase: Phase::RolloverHeader,
                ordinal: n,
            },
            format!("换代更新 新扇区头字节#{n}"),
            &mut results,
        );
    }
    // carry 记录 104 字节
    for n in 1..=104u64 {
        push_cut(
            Cut::RecordByte {
                phase: Phase::RolloverCarry,
                ordinal: n,
            },
            format!("换代更新 carry记录字节#{n}"),
            &mut results,
        );
    }
    // 新发布记录 104 字节
    for n in 1..=104u64 {
        push_cut(
            Cut::RecordByte {
                phase: Phase::WriteRecord,
                ordinal: n,
            },
            format!("换代更新 新发布记录字节#{n}"),
            &mut results,
        );
    }

    // 多代循环：无故障连续推进到 v120（经历三次换代），每步都必须选到最新完整版本
    let mut flash = advance_to(1, size, 38);
    for v in 39u32..=120 {
        let pkg = Package::new(v, make_firmware(v, size));
        let mut fx = Fixture::default();
        let out = updater::run_update(&mut flash, &pkg, &mut fx).unwrap();
        let r = inspect(&flash);
        let c = r.chosen.as_ref().unwrap();
        let ok = c.version == v && c.slot == out.slot;
        results.push(TrialResult {
            cut: format!("多代推进 v{v}"),
            reboot_slot: c.slot,
            reboot_version: c.version,
            reboot_reason: crate::boot::reason_text(&r),
            reached_version: v,
            ok,
            detail: if ok {
                String::new()
            } else {
                format!("期望槽 {} 版本 v{}", out.slot, v)
            },
        });
    }
    // 换代次数核对：38 条/代，generation 应已推进
    let r = inspect(&flash);
    let final_gen = r.chosen.as_ref().unwrap().generation;
    results.push(TrialResult {
        cut: "多代推进换代号".into(),
        reboot_slot: r.chosen.as_ref().unwrap().slot,
        reboot_version: 120,
        reboot_reason: String::new(),
        reached_version: 120,
        ok: final_gen >= 3,
        detail: if final_gen >= 3 {
            format!("最终换代号 generation={final_gen}")
        } else {
            format!("期望至少换代到 generation>=3，实际 generation={final_gen}")
        },
    });

    results
}
