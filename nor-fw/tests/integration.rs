//! 端到端集成测试：NOR 语义、更新约束、半包隔离、换代保护。

use nor_fw::boot::inspect;
use nor_fw::flash::{Cut, ErasePattern, Fixture, Flash, NorError};
use nor_fw::layout::SLOT_SIZE;
use nor_fw::package::Package;
use nor_fw::replay::make_firmware;
use nor_fw::updater;

fn provisioned(len: usize) -> Flash {
    let mut f = Flash::blank();
    updater::factory_provision(&mut f, 1, &make_firmware(1, len)).unwrap();
    f
}

fn update_ok(f: &mut Flash, v: u32, len: usize) {
    let pkg = Package::new(v, make_firmware(v, len));
    let mut fx = Fixture::default();
    updater::run_update(f, &pkg, &mut fx).expect("无故障更新必须成功");
}

#[test]
fn nor_program_is_one_to_zero_only() {
    let mut f = Flash::blank();
    f.program_byte_raw(0, 0x0F).unwrap();
    // 0x0F | 试图再清回 1 必须失败
    assert!(matches!(
        f.program_byte_raw(0, 0xFF),
        Err(NorError::ProgramConflict { .. })
    ));
    // 继续向 0 编程合法
    f.program_byte_raw(0, 0x03).unwrap();
    assert_eq!(f.byte_at(0), 0x03);
    f.erase_sector_raw(0).unwrap();
    assert_eq!(f.byte_at(0), 0xFF);
}

#[test]
fn updates_alternate_slots_and_monotonic_versions() {
    let mut f = provisioned(1000);
    let mut expect_slot = 0u8;
    for v in 2..=10 {
        update_ok(&mut f, v, 1000);
        let r = inspect(&f);
        let c = r.chosen.unwrap();
        expect_slot = 1 - expect_slot;
        assert_eq!(c.version, v);
        assert_eq!(c.slot, expect_slot, "v{v} 应落在另一槽");
    }
}

#[test]
fn rejects_non_increment_version() {
    let mut f = provisioned(100);
    let same = Package::new(1, make_firmware(1, 100));
    let mut fx = Fixture::default();
    assert!(updater::run_update(&mut f, &same, &mut fx).is_err());
    let older = Package::new(0, make_firmware(0, 100));
    assert!(updater::run_update(&mut f, &older, &mut fx).is_err());
    // 闪存内容未被破坏
    assert_eq!(inspect(&f).chosen.unwrap().version, 1);
}

#[test]
fn rejects_oversized_firmware() {
    let mut f = provisioned(10);
    let big = Package::new(2, make_firmware(2, SLOT_SIZE + 1));
    let mut fx = Fixture::default();
    assert!(updater::run_update(&mut f, &big, &mut fx).is_err());
}

#[test]
fn torn_record_is_skipped_not_halfbooted() {
    let mut f = provisioned(300);
    let pkg = Package::new(2, make_firmware(2, 300));
    // commit 魔数只写了一半
    let cut = Cut::RecordByte {
        phase: nor_fw::flash::Phase::WriteRecord,
        ordinal: 100,
    };
    let mut fx = Fixture::new(cut);
    assert!(matches!(
        updater::run_update(&mut f, &pkg, &mut fx),
        Err(NorError::PowerCut)
    ));
    let r = inspect(&f);
    let c = r.chosen.expect("旧版本必须仍可启动");
    assert_eq!(c.version, 1, "半包记录不得被当成 v2 启动");
    assert!(!r.skipped.is_empty(), "应报告被跳过的损坏记录");
}

#[test]
fn partially_erased_slot_does_not_boot() {
    let mut f = provisioned(300);
    let pkg = Package::new(2, make_firmware(2, 300));
    let cut = Cut::Erase {
        ordinal: 2,
        pattern: ErasePattern::Checker,
    };
    let mut fx = Fixture::new(cut);
    assert!(matches!(
        updater::run_update(&mut f, &pkg, &mut fx),
        Err(NorError::PowerCut)
    ));
    let r = inspect(&f);
    assert_eq!(r.chosen.unwrap().version, 1);
}

#[test]
fn power_loss_at_every_record_byte_is_recoverable() {
    // 104 个发布记录字节切点全部独立复演
    for n in 1..=104u64 {
        let base = provisioned(300);
        let pkg = Package::new(2, make_firmware(2, 300));
        let cut = Cut::RecordByte {
            phase: nor_fw::flash::Phase::WriteRecord,
            ordinal: n,
        };
        let mut f = Flash::from_image(base.image());
        let mut fx = Fixture::new(cut);
        let _ = updater::run_update(&mut f, &pkg, &mut fx);
        let after_cut = inspect(&f).chosen.unwrap().version;
        assert!(
            after_cut == 1 || after_cut == 2,
            "记录字节 {n} 切点后选中了非法版本 {after_cut}"
        );
        if after_cut == 2 {
            // 切点落在第 104 字节（commit 已完整）：新版本已发布，
            // 同版本重试必须被「版本递增」规则拒绝
            let mut fx2 = Fixture::default();
            let err = updater::run_update(&mut f, &pkg, &mut fx2).unwrap_err();
            assert!(matches!(err, NorError::Rejected(_)));
        } else {
            // commit 未完成：无故障重试必然到达 v2
            update_ok(&mut f, 2, 300);
            assert_eq!(inspect(&f).chosen.unwrap().version, 2);
        }
    }
}

#[test]
fn rollover_preserves_last_bootable_across_generations() {
    // 推进到写满记录扇区（38 条）并跨越换代
    let mut f = provisioned(200);
    for v in 2..=45 {
        update_ok(&mut f, v, 200);
    }
    let r = inspect(&f);
    let c = r.chosen.unwrap();
    assert_eq!(c.version, 45);
    assert!(c.generation >= 2, "应已换代，实际 gen={}", c.generation);
    // 换代后旧版本记录仍保留为候选（carry），且数据校验可区分
    assert!(
        r.candidates.iter().any(|x| x.fields.version == 44),
        "上一代最后版本应被搬运保留"
    );
}

#[test]
fn rollover_carry_cut_keeps_old_version_then_recovers() {
    let mut f = provisioned(200);
    for v in 2..=38 {
        update_ok(&mut f, v, 200);
    }
    let pkg = Package::new(39, make_firmware(39, 200));
    let cut = Cut::RecordByte {
        phase: nor_fw::flash::Phase::RolloverCarry,
        ordinal: 50,
    };
    let mut fx = Fixture::new(cut);
    assert!(matches!(
        updater::run_update(&mut f, &pkg, &mut fx),
        Err(NorError::PowerCut)
    ));
    assert_eq!(inspect(&f).chosen.unwrap().version, 38);
    let mut fx2 = Fixture::default();
    updater::run_update(&mut f, &pkg, &mut fx2).unwrap();
    assert_eq!(inspect(&f).chosen.unwrap().version, 39);
}
