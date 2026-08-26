use assert_cmd::Command;

#[test]
fn account_add_and_list_share_a_versioned_json_contract() {
    let directory = tempfile::tempdir().expect("temp dir");
    let config = directory.path().join("accounts.toml");

    let added = Command::cargo_bin("kirje")
        .expect("kirje binary")
        .args([
            "--config",
            config.to_str().expect("config path"),
            "account",
            "add",
            "personal",
            "agent@163.com",
        ])
        .output()
        .expect("run account add");
    assert!(added.status.success());
    let added_json: serde_json::Value =
        serde_json::from_slice(&added.stdout).expect("account add JSON");
    assert_eq!(added_json["ok"], true);
    assert_eq!(added_json["data"]["incoming"]["host"], "imap.163.com");

    let listed = Command::cargo_bin("kirje")
        .expect("kirje binary")
        .args([
            "--config",
            config.to_str().expect("config path"),
            "account",
            "list",
        ])
        .output()
        .expect("run account list");
    assert!(listed.status.success());
    let listed_json: serde_json::Value =
        serde_json::from_slice(&listed.stdout).expect("account list JSON");
    assert_eq!(
        listed_json["contract_version"],
        added_json["contract_version"]
    );
    assert_eq!(listed_json["data"][0]["id"], "personal");
}

#[test]
fn secret_input_is_rejected_outside_a_tty_and_never_echoed() {
    let directory = tempfile::tempdir().expect("temp dir");
    let config = directory.path().join("accounts.toml");
    Command::cargo_bin("kirje")
        .expect("kirje binary")
        .args([
            "--config",
            config.to_str().expect("config path"),
            "account",
            "add",
            "personal",
            "agent@163.com",
        ])
        .assert()
        .success();

    let output = Command::cargo_bin("kirje")
        .expect("kirje binary")
        .args([
            "--config",
            config.to_str().expect("config path"),
            "secret",
            "set",
            "personal",
        ])
        .write_stdin("must-not-leak")
        .output()
        .expect("run secret set");
    assert_eq!(output.status.code(), Some(2));
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(!stdout.contains("must-not-leak"));
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("error JSON");
    assert_eq!(json["error"]["code"], "invalid_input");
}

#[test]
fn malformed_commands_return_json_and_exit_two() {
    let output = Command::cargo_bin("kirje")
        .expect("kirje binary")
        .args(["message", "read", "--uid", "not-a-number"])
        .output()
        .expect("run malformed command");
    assert_eq!(output.status.code(), Some(2));
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("invalid input JSON");
    assert_eq!(json["ok"], false);
    assert_eq!(json["error"]["code"], "invalid_input");
}
