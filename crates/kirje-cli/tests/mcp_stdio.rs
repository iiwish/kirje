use assert_cmd::Command;

#[test]
fn stdio_handshake_is_protocol_clean_and_declares_local_write_safety() {
    let directory = tempfile::tempdir().expect("temp dir");
    let config = directory.path().join("accounts.toml");
    let index = directory.path().join("index.sqlite3");
    let outbox = directory.path().join("outbox.sqlite3");
    let requests = concat!(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"contract-test\",\"version\":\"1\"}}}\n",
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}\n",
    );
    let output = Command::cargo_bin("kirje")
        .expect("kirje binary")
        .args([
            "--config",
            config.to_str().expect("config"),
            "--index",
            index.to_str().expect("index"),
            "--outbox",
            outbox.to_str().expect("outbox"),
            "mcp",
            "serve",
        ])
        .write_stdin(requests)
        .output()
        .expect("run MCP server");
    assert!(output.status.success());

    let responses: Vec<serde_json::Value> = String::from_utf8(output.stdout)
        .expect("utf8 stdout")
        .lines()
        .map(|line| serde_json::from_str(line).expect("one JSON-RPC object per line"))
        .collect();
    assert_eq!(responses.len(), 2, "stdout must contain only MCP responses");
    assert_eq!(responses[0]["result"]["serverInfo"]["name"], "kirje");

    let tools = responses[1]["result"]["tools"]
        .as_array()
        .expect("tool array");
    let names: Vec<&str> = tools
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect();
    assert_eq!(names.len(), 13);
    assert!(names.contains(&"mailbox_list"));
    assert!(names.contains(&"mailbox_sync"));
    assert!(names.contains(&"message_search_local"));
    assert!(names.contains(&"attachment_read"));
    let sync = tools
        .iter()
        .find(|tool| tool["name"] == "mailbox_sync")
        .expect("sync tool");
    assert_eq!(sync["annotations"]["readOnlyHint"], false);
    assert_eq!(sync["annotations"]["destructiveHint"], false);
    let local_search = tools
        .iter()
        .find(|tool| tool["name"] == "message_search_local")
        .expect("local search tool");
    assert_eq!(local_search["annotations"]["readOnlyHint"], true);
    assert_eq!(local_search["annotations"]["openWorldHint"], false);
    assert!(names.contains(&"message_send_plan"));
    assert!(names.contains(&"message_send_status"));
    assert!(names.contains(&"message_send_apply"));
    assert!(!names.iter().any(|name| name.contains("approve")));
}
