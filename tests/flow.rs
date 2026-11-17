//! The DKG with each member in its own process, exchanging files: they all
//! reach the same group key, and no member's folder holds another's secret.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn tool() -> Command {
    Command::new(env!("CARGO_BIN_EXE_tz4-threshold"))
}

fn run(args: &[&str]) -> String {
    let out = tool().args(args).output().expect("the tool runs");
    assert!(
        out.status.success(),
        "{args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn fresh_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tz4-threshold-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    dir
}

#[test]
fn members_in_separate_processes_agree_on_one_key() {
    let dir = fresh_dir("flow");
    let g = dir.to_str().unwrap();
    for id in ["1", "2", "3"] {
        run(&[
            "member", "dkg1", "--group", g, "--id", id, "--t", "2", "--n", "3",
        ]);
    }
    for id in ["1", "2", "3"] {
        run(&["member", "dkg2", "--group", g, "--id", id]);
    }
    for id in ["1", "2", "3"] {
        run(&["member", "dkg3", "--group", g, "--id", id]);
    }
    let agreed = run(&["coord", "group", "--group", g]);
    assert!(agreed.starts_with("3 members agree: tz4"), "{agreed}");

    // Each private folder ends with its own key share only: the round secrets
    // are deleted and no file names another member.
    for id in 1..=3 {
        let mut names: Vec<String> = fs::read_dir(dir.join(format!("member-{id}")))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        assert_eq!(names, ["key.json", "params.json"]);
    }
    let shares: Vec<String> = (1..=3)
        .map(|id| {
            let key: serde_json::Value = serde_json::from_str(
                &fs::read_to_string(dir.join(format!("member-{id}/key.json"))).unwrap(),
            )
            .unwrap();
            key["share"].as_str().unwrap().to_string()
        })
        .collect();
    assert!(shares[0] != shares[1] && shares[1] != shares[2] && shares[0] != shares[2]);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_member_cannot_start_a_second_dkg_in_the_same_group() {
    let dir = fresh_dir("twice");
    let g = dir.to_str().unwrap();
    run(&[
        "member", "dkg1", "--group", g, "--id", "1", "--t", "2", "--n", "3",
    ]);
    let out = tool()
        .args([
            "member", "dkg1", "--group", g, "--id", "1", "--t", "2", "--n", "3",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("already started"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn round_two_waits_for_every_round_one() {
    let dir = fresh_dir("wait");
    let g = dir.to_str().unwrap();
    run(&[
        "member", "dkg1", "--group", g, "--id", "1", "--t", "2", "--n", "3",
    ]);
    run(&[
        "member", "dkg1", "--group", g, "--id", "2", "--t", "2", "--n", "3",
    ]);
    let out = tool()
        .args(["member", "dkg2", "--group", g, "--id", "1"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("member 3 has not published round 1"));
    let _ = fs::remove_dir_all(&dir);
}
