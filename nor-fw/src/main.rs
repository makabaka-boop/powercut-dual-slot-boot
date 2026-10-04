//! 命令行入口。
//!
//! 子命令：
//! - `factory  <镜像> [--len N]`             工厂预置 v1 可启动固件
//! - `pack     <版本> <长度> <输出.pkg>`      生成确定性测试更新包
//! - `boot     <镜像> [--json]`               启动检查，报告所选槽/版本/依据
//! - `update   <镜像> --pkg <包> [切点...]`   执行更新（可注入掉电）
//! - `status   <镜像>`                        打印记录区扫描明细
//! - `replay   [--small|--rollover|--all]`    掉电复演（默认 --all）
//!
//! 更新切点（互斥，指定一个）：
//! - `--cut-erase=<第次擦除>:<图案>`  图案：zero|keep-head|keep-tail|checker|stripes
//! - `--cut-page=<页>:<页内字节>`    均从 1 开始，含 0xFF 填充字节
//! - `--cut-record=阶段:字节`        阶段：header|carry|record
//!
//! 掉电时镜像文件保留断点内容并以退出码 3 返回；重开后直接 `boot` 即可复演。

use nor_fw::boot::inspect;
use nor_fw::flash::{Cut, ErasePattern, Fixture, Flash, NorError, Phase};
use nor_fw::layout::{classify_header, classify_record, RecAddr, FLASH_SIZE, RECORDS_PER_SECTOR};
use nor_fw::package::Package;
use nor_fw::replay;
use nor_fw::updater;
use std::process::ExitCode;

fn usage() -> String {
    include_str!("usage.txt").to_string()
}

fn load_flash(path: &str) -> Flash {
    let img = std::fs::read(path).unwrap_or_else(|e| fatal(&format!("读取镜像 {path} 失败：{e}")));
    if img.len() != FLASH_SIZE {
        fatal(&format!(
            "镜像大小 {} 字节，应为 {FLASH_SIZE}；请先执行 factory",
            img.len()
        ));
    }
    Flash::from_image(&img)
}

fn save_flash(path: &str, flash: &Flash) {
    if let Err(e) = std::fs::write(path, flash.image()) {
        fatal(&format!("写镜像 {path} 失败：{e}"));
    }
}

fn fatal(msg: &str) -> ! {
    eprintln!("错误：{msg}");
    std::process::exit(2);
}

fn parse_cut(args: &[String]) -> Cut {
    let mut cut = Cut::None;
    for a in args {
        if let Some(v) = a.strip_prefix("--cut-erase=") {
            let (n, pat) = v
                .split_once(':')
                .unwrap_or_else(|| fatal("--cut-erase 格式为 次数:图案"));
            let ordinal: u64 = n.parse().unwrap_or_else(|_| fatal("--cut-erase 次数应为数字"));
            let pattern = ErasePattern::parse(pat).unwrap_or_else(|| {
                fatal("未知擦除图案（zero/keep-head/keep-tail/checker/stripes）")
            });
            cut = Cut::Erase { ordinal, pattern };
        } else if let Some(v) = a.strip_prefix("--cut-page=") {
            let (p, b) = v
                .split_once(':')
                .unwrap_or_else(|| fatal("--cut-page 格式为 页:字节"));
            cut = Cut::PageByte {
                page: p.parse().unwrap_or_else(|_| fatal("页号应为数字")),
                byte_in_page: b.parse().unwrap_or_else(|_| fatal("字节序号应为数字")),
            };
        } else if let Some(v) = a.strip_prefix("--cut-record=") {
            let (ph, n) = v
                .split_once(':')
                .unwrap_or_else(|| fatal("--cut-record 格式为 阶段:字节"));
            let phase = match ph {
                "header" => Phase::RolloverHeader,
                "carry" => Phase::RolloverCarry,
                "record" => Phase::WriteRecord,
                _ => fatal("阶段应为 header|carry|record"),
            };
            cut = Cut::RecordByte {
                phase,
                ordinal: n.parse().unwrap_or_else(|_| fatal("字节序号应为数字")),
            };
        } else {
            fatal(&format!("未知参数 {a}"));
        }
    }
    cut
}

fn cmd_factory(args: &[String]) -> ExitCode {
    let path = args
        .first()
        .cloned()
        .unwrap_or_else(|| fatal("缺少镜像路径"));
    let mut len = 1024usize;
    for a in &args[1..] {
        if let Some(v) = a.strip_prefix("--len=") {
            len = v.parse().unwrap_or_else(|_| fatal("--len..."));
        } else {
            fatal(&format!("未知参数 {a}"));
        }
    }
    if len > nor_fw::layout::SLOT_SIZE {
        fatal("固件超过槽容量");
    }
    let mut flash = Flash::blank();
    let seed = replay::make_firmware(1, len);
    updater::factory_provision(&mut flash, 1, &seed)
        .unwrap_or_else(|e| fatal(&e.to_string()));
    save_flash(&path, &flash);
    println!("已在 {path} 工厂预置：槽0，v1，{len} 字节（器件 {FLASH_SIZE} 字节）");
    ExitCode::SUCCESS
}

fn cmd_pack(args: &[String]) -> ExitCode {
    if args.len() < 3 {
        fatal("用法：pack <版本> <长度> <输出.pkg>");
    }
    let version: u32 = args[0].parse().unwrap_or_else(|_| fatal("版本应为数字"));
    let len: usize = args[1].parse().unwrap_or_else(|_| fatal("长度应为数字"));
    let out = &args[2];
    if len > nor_fw::layout::SLOT_SIZE {
        fatal("固件超过槽容量");
    }
    let pkg = Package::new(version, replay::make_firmware(version, len));
    std::fs::write(out, pkg.encode()).unwrap_or_else(|e| fatal(&format!("写包失败：{e}")));
    println!(
        "已生成更新包 {out}：v{version}，{len} 字节，SHA-256 {}",
        hash_hex(&pkg.hash)
    );
    ExitCode::SUCCESS
}

fn hash_hex(h: &[u8; 32]) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect()
}

fn cmd_boot(args: &[String]) -> ExitCode {
    let path = args
        .first()
        .cloned()
        .unwrap_or_else(|| fatal("缺少镜像路径"));
    let json = args[1..].contains(&"--json".to_string());
    let flash = load_flash(&path);
    let r = inspect(&flash);
    let reason = nor_fw::boot::reason_text(&r);
    if json {
        match &r.chosen {
            Some(c) => println!(
                "{{\"bootable\":true,\"slot\":{},\"version\":{},\"seq\":{},\"generation\":{},\"len\":{},\"reason\":{}}}",
                c.slot,
                c.version,
                c.seq,
                c.generation,
                c.data_len,
                json_escape(&reason)
            ),
            None => println!(
                "{{\"bootable\":false,\"reason\":{}}}",
                json_escape(&reason)
            ),
        }
    } else {
        match &r.chosen {
            Some(c) => {
                println!("可启动：槽{}  v{}", c.slot, c.version);
                println!("依据：{reason}");
            }
            None => {
                println!("无可启动固件");
                println!("依据：{reason}");
            }
        }
        if !r.skipped.is_empty() {
            println!("跳过的损坏/未完成记录 {} 条：", r.skipped.len());
            for s in r.skipped.iter().take(10) {
                println!("  - 记录扇区{} idx{}：{}", s.addr.rs, s.addr.idx, s.why);
            }
            if r.skipped.len() > 10 {
                println!("  …（其余 {} 条省略）", r.skipped.len() - 10);
            }
        }
    }
    if r.chosen.is_some() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(4)
    }
}

fn json_escape(s: &str) -> String {
    let mut out = String::from("\"");
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn cmd_update(args: &[String]) -> ExitCode {
    let mut img_path = None;
    let mut pkg_path = None;
    let mut cut_args = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--pkg" => pkg_path = it.next().cloned(),
            s if s.starts_with("--cut-") => cut_args.push(a.clone()),
            _ if img_path.is_none() => img_path = Some(a.clone()),
            _ => fatal(&format!("未知参数 {a}")),
        }
    }
    let img_path = img_path.unwrap_or_else(|| fatal("用法：update <镜像> --pkg <包> [切点]"));
    let pkg_path = pkg_path.unwrap_or_else(|| fatal("缺少 --pkg"));
    let cut = parse_cut(&cut_args);

    let mut flash = load_flash(&img_path);
    let pkg_buf = std::fs::read(&pkg_path).unwrap_or_else(|e| fatal(&format!("读包失败：{e}")));
    let pkg = Package::decode(&pkg_buf).unwrap_or_else(|e| fatal(&e));

    let mut fx = Fixture::new(cut);
    match updater::run_update(&mut flash, &pkg, &mut fx) {
        Ok(o) => {
            save_flash(&img_path, &flash);
            println!(
                "更新完成并发布：槽{} v{}（序号 {}，换代号 {}，{}）",
                o.slot,
                o.version,
                o.seq,
                o.generation,
                if o.rolled_over { "记录区换代" } else { "追加记录" }
            );
            ExitCode::SUCCESS
        }
        Err(NorError::PowerCut) => {
            save_flash(&img_path, &flash);
            eprintln!("⚠ 掉电：{}", fx.last_label);
            eprintln!("镜像已保留断点状态，重开后请执行 boot 检查启动选择。");
            ExitCode::from(3)
        }
        Err(NorError::Rejected(msg)) => {
            // 预检拒绝发生在任何擦写之前，镜像不变，不写回
            eprintln!("更新被拒绝：{msg}");
            ExitCode::from(5)
        }
        Err(e) => {
            save_flash(&img_path, &flash);
            eprintln!("更新失败：{e}");
            ExitCode::from(2)
        }
    }
}

fn cmd_status(args: &[String]) -> ExitCode {
    let path = args
        .first()
        .cloned()
        .unwrap_or_else(|| fatal("缺少镜像路径"));
    let flash = load_flash(&path);
    for rs in 0..nor_fw::layout::NUM_REC_SECTORS {
        let hdr = classify_header(flash.image(), rs);
        println!("记录扇区 {rs}：头部 {hdr:?}");
        for idx in 0..RECORDS_PER_SECTOR {
            match classify_record(flash.image(), RecAddr::new(rs, idx)) {
                nor_fw::layout::RecKind::Empty => {}
                nor_fw::layout::RecKind::Torn => {
                    println!("  idx{idx:2}: 损坏/未完成（忽略）");
                }
                nor_fw::layout::RecKind::Committed(f) => {
                    println!(
                        "  idx{idx:2}: seq={:<4} slot={} v{:<4} len={:<6} fwhash={:.8}…",
                        f.seq,
                        f.slot,
                        f.version,
                        f.data_len,
                        hash_hex(&f.fw_hash)
                    );
                }
            }
        }
    }
    let r = inspect(&flash);
    println!("=> {}", nor_fw::boot::reason_text(&r));
    ExitCode::SUCCESS
}

fn print_failures(fails: &[replay::TrialResult], limit: usize) {
    for t in fails.iter().take(limit) {
        eprintln!("  失败 [{}]：{}", t.cut, t.detail);
    }
    if fails.len() > limit {
        eprintln!("  …另有 {} 条失败省略", fails.len() - limit);
    }
}

/// 报告一组试次：总数、重开选择分布，以及代表性试次的槽/版本/依据。
/// `verbose` 时逐条打印每个切点的槽/版本/依据。
fn report_group(title: &str, results: &[replay::TrialResult], verbose: bool) -> bool {
    println!("== {title} ==");
    let total = results.len();
    let fails: Vec<&replay::TrialResult> = results.iter().filter(|r| !r.ok).collect();
    let s = replay::summarize(results);
    println!(
        "试次 {total}，失败 {}；重开后选旧完整版本 {}，选已发布新版本 {}，重试后全部恢复 {}",
        fails.len(),
        s.boot_old,
        s.boot_new,
        s.recovered
    );
    print_failures(
        &fails.iter().map(|r| (*r).clone()).collect::<Vec<_>>(),
        20,
    );

    if verbose {
        println!("全部切口明细：");
        for r in results {
            println!(
                "  「{}」→ 槽{} v{}（重开）",
                r.cut, r.reboot_slot, r.reboot_version
            );
            println!("      依据：{}", r.reboot_reason);
        }
    } else {
        // 代表性试次：各取「选旧」与「选新」一例
        let mut sample_old = None;
        let mut sample_new = None;
        for r in results {
            if !r.ok {
                continue;
            }
            if r.reboot_version < r.reached_version && sample_old.is_none() {
                sample_old = Some(r);
            } else if r.reboot_version >= r.reached_version && sample_new.is_none() {
                sample_new = Some(r);
            }
            if sample_old.is_some() && sample_new.is_some() {
                break;
            }
        }
        println!("代表性试次（重开电源后的选择）：");
        for (pick, r) in [
            ("选旧完整版本", sample_old),
            ("选已完整发布新版本", sample_new),
        ] {
            if let Some(r) = r {
                println!(
                    "  [{pick}] 切点「{}」→ 槽{} v{}",
                    r.cut, r.reboot_slot, r.reboot_version
                );
                println!("      依据：{}", r.reboot_reason);
            } else {
                println!("  [{pick}] 本组无此类切点");
            }
        }
    }
    fails.is_empty()
}

fn cmd_replay(args: &[String]) -> ExitCode {
    let verbose = args.contains(&"--verbose".to_string());
    let mode = args
        .iter()
        .find(|a| a.as_str() != "--verbose")
        .cloned()
        .unwrap_or_else(|| "--all".to_string());
    if mode != "--small" && mode != "--rollover" && mode != "--all" {
        fatal("用法：replay [--small|--rollover|--all] [--verbose]");
    }
    let mut ok = true;

    if mode == "--small" || mode == "--all" {
        let results = replay::sweep_small_firmware();
        ok &= report_group(
            "小固件全部切口遍历（尺寸 1/255/256/257/511/512/513）",
            &results,
            verbose,
        );
    }
    if mode == "--rollover" || mode == "--all" {
        let results = replay::sweep_rollover();
        ok &= report_group(
            "记录区换代（写满 38 条触发换代 + 多代循环到 v120）",
            &results,
            verbose,
        );
    }

    if ok {
        println!("全部通过：任何掉电点重开后均选中旧完整版本或已完整发布的新版本，未误用半包。");
        ExitCode::SUCCESS
    } else {
        eprintln!("存在失败试次！");
        ExitCode::from(1)
    }
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    if argv.len() < 2 {
        print!("{}", usage());
        return ExitCode::SUCCESS;
    }
    let rest = &argv[2..];
    match argv[1].as_str() {
        "factory" => cmd_factory(rest),
        "pack" => cmd_pack(rest),
        "update" => cmd_update(rest),
        "boot" => cmd_boot(rest),
        "status" => cmd_status(rest),
        "replay" => cmd_replay(rest),
        "-h" | "--help" | "help" => {
            print!("{}", usage());
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("未知子命令：{other}\n");
            print!("{}", usage());
            ExitCode::from(2)
        }
    }
}
