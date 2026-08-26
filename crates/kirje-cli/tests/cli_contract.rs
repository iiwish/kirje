use assert_cmd::Command;

#[test]
fn provider_registry_is_inspectable_without_configuration_or_credentials() {
    let list = Command::cargo_bin("kirje")
        .expect("kirje binary")
        .args(["provider", "list"])
        .output()
        .expect("provider list");
    assert!(list.status.success());
    let list_json: serde_json::Value =
        serde_json::from_slice(&list.stdout).expect("provider list JSON");
    assert_eq!(list_json["data"]["schema_version"], 1);
    assert!(
        list_json["data"]["returned"]
            .as_u64()
            .is_some_and(|count| count <= 128)
    );

    let show = Command::cargo_bin("kirje")
        .expect("kirje binary")
        .args(["provider", "show", "163.com"])
        .output()
        .expect("provider show");
    assert!(show.status.success());
    let show_json: serde_json::Value =
        serde_json::from_slice(&show.stdout).expect("provider show JSON");
    assert_eq!(show_json["data"]["id"], "netease-163");
    assert!(
        show_json["data"]["endpoints"]
            .as_array()
            .expect("endpoints")
            .iter()
            .any(|endpoint| endpoint["protocol"] == "pop3" && endpoint["runtime_default"] == false)
    );
}

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

#[test]
fn empty_local_index_status_and_search_need_no_secret() {
    let directory = tempfile::tempdir().expect("temp dir");
    let config = directory.path().join("accounts.toml");
    let index = directory.path().join("index.sqlite3");
    Command::cargo_bin("kirje")
        .expect("kirje binary")
        .args([
            "--config",
            config.to_str().expect("config path"),
            "--index",
            index.to_str().expect("index path"),
            "account",
            "add",
            "personal",
            "agent@163.com",
        ])
        .assert()
        .success();

    let status = Command::cargo_bin("kirje")
        .expect("kirje binary")
        .args([
            "--config",
            config.to_str().expect("config path"),
            "--index",
            index.to_str().expect("index path"),
            "sync",
            "status",
            "--account",
            "personal",
            "--mailbox",
            "INBOX",
        ])
        .output()
        .expect("sync status");
    assert!(status.status.success());
    let status_json: serde_json::Value =
        serde_json::from_slice(&status.stdout).expect("status JSON");
    assert!(status_json["data"].is_null());

    let search = Command::cargo_bin("kirje")
        .expect("kirje binary")
        .args([
            "--config",
            config.to_str().expect("config path"),
            "--index",
            index.to_str().expect("index path"),
            "message",
            "search-local",
            "--account",
            "personal",
            "--mailbox",
            "INBOX",
        ])
        .output()
        .expect("local search");
    assert!(search.status.success());
    let search_json: serde_json::Value =
        serde_json::from_slice(&search.stdout).expect("search JSON");
    assert_eq!(search_json["data"]["returned"], 0);
    assert_eq!(search_json["data"]["untrusted"], true);
}

#[test]
fn relative_config_and_index_paths_are_supported() {
    let directory = tempfile::tempdir().expect("temp dir");
    let output = Command::cargo_bin("kirje")
        .expect("kirje binary")
        .current_dir(directory.path())
        .args([
            "--config",
            "accounts.toml",
            "--index",
            "index.sqlite3",
            "account",
            "add",
            "personal",
            "agent@163.com",
        ])
        .output()
        .expect("relative account add");

    assert!(output.status.success());
    assert!(directory.path().join("accounts.toml").is_file());
    assert!(directory.path().join("index.sqlite3").is_file());
}
