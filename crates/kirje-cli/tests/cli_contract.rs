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
    assert_eq!(added_json["data"]["outgoing"]["host"], "smtp.163.com");
    assert_eq!(added_json["data"]["outgoing"]["port"], 465);

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

    let duplicate = Command::cargo_bin("kirje")
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
        .expect("run duplicate account add");
    assert_eq!(duplicate.status.code(), Some(1));
    let duplicate_json: serde_json::Value =
        serde_json::from_slice(&duplicate.stdout).expect("duplicate JSON");
    assert_eq!(duplicate_json["error"]["code"], "account_already_exists");
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

    let thread = Command::cargo_bin("kirje")
        .expect("kirje binary")
        .args([
            "--config",
            config.to_str().expect("config path"),
            "--index",
            index.to_str().expect("index path"),
            "message",
            "thread",
            "--account",
            "personal",
            "--mailbox",
            "INBOX",
            "--uid",
            "1",
        ])
        .output()
        .expect("thread query");
    assert!(thread.status.success());
    let thread_json: serde_json::Value =
        serde_json::from_slice(&thread.stdout).expect("thread JSON");
    assert!(thread_json["data"].is_null());
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

#[test]
#[allow(clippy::too_many_lines)]
fn send_plan_is_local_and_approval_rejects_piped_input() {
    let directory = tempfile::tempdir().expect("temp dir");
    let config = directory.path().join("accounts.toml");
    let index = directory.path().join("index.sqlite3");
    let outbox = directory.path().join("outbox.sqlite3");
    let request = directory.path().join("send.json");
    std::fs::write(
        &request,
        r#"{
            "account_id":"personal",
            "to":[{"name":null,"email":"agent@163.com"}],
            "cc":[],
            "bcc":[],
            "subject":"CLI governed send",
            "text":"local planning only",
            "html":null
        }"#,
    )
    .expect("request");
    let common = [
        "--config",
        config.to_str().expect("config"),
        "--index",
        index.to_str().expect("index"),
        "--outbox",
        outbox.to_str().expect("outbox"),
    ];
    Command::cargo_bin("kirje")
        .expect("kirje binary")
        .args(common)
        .args(["account", "add", "personal", "agent@163.com"])
        .assert()
        .success();

    // Verify default policy is read-only for remote writes (FR-014)
    let default_policy = Command::cargo_bin("kirje")
        .expect("kirje binary")
        .args(common)
        .args(["policy", "show", "personal"])
        .output()
        .expect("policy show");
    assert!(default_policy.status.success());
    let policy_json: serde_json::Value =
        serde_json::from_slice(&default_policy.stdout).expect("policy JSON");
    assert_eq!(policy_json["data"]["allow_remote_write"], false);

    // Unconfigured/read-only policy rejects send planning
    let rejected_plan = Command::cargo_bin("kirje")
        .expect("kirje binary")
        .args(common)
        .args([
            "send",
            "plan",
            "--input",
            request.to_str().expect("request"),
        ])
        .output()
        .expect("plan rejected");
    assert_eq!(rejected_plan.status.code(), Some(1));
    let rej_json: serde_json::Value =
        serde_json::from_slice(&rejected_plan.stdout).expect("rej JSON");
    assert_eq!(rej_json["error"]["code"], "unsupported_capability");

    // Enable governed remote write for personal account
    Command::cargo_bin("kirje")
        .expect("kirje binary")
        .args(common)
        .args(["policy", "enable", "personal"])
        .assert()
        .success();

    let planned = Command::cargo_bin("kirje")
        .expect("kirje binary")
        .args(common)
        .args([
            "send",
            "plan",
            "--input",
            request.to_str().expect("request"),
        ])
        .output()
        .expect("plan");
    assert!(planned.status.success());
    let planned: serde_json::Value = serde_json::from_slice(&planned.stdout).expect("plan JSON");
    let plan_id = planned["data"]["id"].as_str().expect("plan id");
    assert_eq!(planned["data"]["status"], "planned");

    let approval = Command::cargo_bin("kirje")
        .expect("kirje binary")
        .args(common)
        .args(["send", "approve", plan_id])
        .write_stdin(plan_id)
        .output()
        .expect("approve");
    assert_eq!(approval.status.code(), Some(2));
    let approval: serde_json::Value =
        serde_json::from_slice(&approval.stdout).expect("approval JSON");
    assert_eq!(approval["error"]["code"], "invalid_input");

    let status = Command::cargo_bin("kirje")
        .expect("kirje binary")
        .args(common)
        .args(["send", "show", plan_id])
        .output()
        .expect("show");
    let status: serde_json::Value = serde_json::from_slice(&status.stdout).expect("status JSON");
    assert_eq!(status["data"]["status"], "planned");

    let apply = Command::cargo_bin("kirje")
        .expect("kirje binary")
        .args(common)
        .args(["send", "apply", plan_id])
        .output()
        .expect("apply");
    assert_eq!(apply.status.code(), Some(1));
    let apply: serde_json::Value = serde_json::from_slice(&apply.stdout).expect("apply JSON");
    assert_eq!(apply["error"]["code"], "send_plan_state");

    let reconcile = Command::cargo_bin("kirje")
        .expect("kirje binary")
        .args(common)
        .args(["send", "reconcile", plan_id, "--assertion", "manual test"])
        .output()
        .expect("reconcile");
    assert_eq!(reconcile.status.code(), Some(1));
    let reconcile: serde_json::Value =
        serde_json::from_slice(&reconcile.stdout).expect("reconcile JSON");
    assert_eq!(reconcile["error"]["code"], "send_plan_state");
}

#[test]
fn attachment_import_is_local_and_returns_a_bounded_summary() {
    let directory = tempfile::tempdir().expect("temp dir");
    let file = directory.path().join("note.txt");
    std::fs::write(&file, "hello from a file").expect("attachment");
    let output = Command::cargo_bin("kirje")
        .expect("kirje binary")
        .args([
            "attachment",
            "import",
            file.to_str().expect("file"),
            "--mime-type",
            "text/plain",
        ])
        .output()
        .expect("import");
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("import JSON");
    assert_eq!(json["data"]["attachment"]["filename"], "note.txt");
    assert_eq!(json["data"]["summary"]["size"], 17);
    assert_eq!(json["data"]["summary"]["text_preview"], "hello from a file");
    assert_eq!(json["data"]["untrusted"], true);
}

#[test]
fn schema_command_matches_stable_contract_golden() {
    let output = Command::cargo_bin("kirje")
        .expect("kirje binary")
        .args(["schema"])
        .output()
        .expect("schema");
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("schema JSON");
    assert_eq!(json["contract_version"], "2026-09-04.1");
    assert_eq!(json["ok"], true);
    assert_eq!(json["data"]["name"], "kirje");
    assert_eq!(json["data"]["version"], env!("CARGO_PKG_VERSION"));

    let commands = json["data"]["commands"].as_array().expect("commands array");
    let names: Vec<&str> = commands
        .iter()
        .map(|cmd| cmd["name"].as_str().expect("name"))
        .collect();

    assert!(names.contains(&"schema"));
    assert!(names.contains(&"doctor"));
    assert!(names.contains(&"account discover <email>"));
    assert!(names.contains(&"provider list|show <id-or-domain>"));
    assert!(names.contains(&"account add|list|status|check"));
    assert!(names.contains(&"secret set|delete <account-id>"));
    assert!(names.contains(&"mailbox list"));
    assert!(names.contains(&"message search|read"));
    assert!(names.contains(&"message search-local"));
    assert!(names.contains(&"sync run|status"));
    assert!(names.contains(&"attachment import|read"));
    assert!(names.contains(&"send plan|from-draft|show|list"));
    assert!(names.contains(&"send approve <plan-id>"));
    assert!(names.contains(&"send apply <plan-id>"));
    assert!(names.contains(&"send reconcile <plan-id> --assertion <text>"));
    assert!(names.contains(&"draft create|show|list|update|discard"));
    assert!(names.contains(&"operation plan|show|list|audit"));
    assert!(names.contains(&"operation approve|apply"));
    assert!(names.contains(&"policy show|set|enable <account>"));
    assert!(names.contains(&"mcp serve"));

    let exit_codes = json["data"]["stable_exit_codes"]
        .as_array()
        .expect("exit codes");
    let codes: Vec<i64> = exit_codes
        .iter()
        .map(|ec| ec["code"].as_i64().expect("code"))
        .collect();
    assert_eq!(codes, vec![0, 1, 2]);
}
