//! Control-plane client tests against a local mock HTTP server.
//!
//! No real network: every test spins up a wiremock server and points the SDK
//! at it with an explicit `api_url`.

use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use xshellz::{
    BoxfileOptions, ConnectOptions, CreateOptions, Error, GetOrCreateOptions, ListOptions, Sandbox,
};

fn shell_json(uuid: &str, status: &str) -> serde_json::Value {
    json!({
        "uuid": uuid,
        "name": "demo",
        "status": status,
        "ssh_command": "ssh -p 42001 root@shellus1.xshellz.com",
        "ssh_host": "shellus1.xshellz.com",
        "ssh_port": 42001,
        "web_terminal_ready": true,
        "trial_ends_at": null,
        "always_on": false,
        "trial_hours_remaining": 719.5,
        "spawned_at": "2026-07-17T00:00:00.000000Z",
        "created_at": "2026-07-17T00:00:00.000000Z",
        "isolation": "gvisor",
        "gvisor": true
    })
}

async fn mock_create(server: &MockServer, response: ResponseTemplate) {
    Mock::given(method("POST"))
        .and(path("/v1/shells/agent"))
        .respond_with(response)
        .mount(server)
        .await;
}

fn create_options(server: &MockServer) -> CreateOptions {
    CreateOptions::default()
        .api_key("test-key")
        .api_url(format!("{}/v1", server.uri()))
}

async fn create_error(server: &MockServer) -> Error {
    Sandbox::create(create_options(server))
        .await
        .expect_err("create must fail")
}

#[tokio::test]
async fn create_sends_generated_public_key_and_name() {
    let server = MockServer::start().await;
    mock_create(
        &server,
        ResponseTemplate::new(200).set_body_json(shell_json("sbx-1", "running")),
    )
    .await;

    let sandbox = Sandbox::create(create_options(&server).name("demo"))
        .await
        .expect("create succeeds");
    sandbox.detach();

    assert_eq!(sandbox.uuid(), "sbx-1");
    assert_eq!(sandbox.status(), "running");
    assert_eq!(sandbox.ssh_host().as_deref(), Some("shellus1.xshellz.com"));
    assert_eq!(sandbox.ssh_port(), Some(42001));
    assert_eq!(
        sandbox.ssh_command().as_deref(),
        Some("ssh -p 42001 root@shellus1.xshellz.com")
    );
    assert!(sandbox
        .private_key_openssh()
        .expect("create keeps the private key")
        .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));

    let requests = server.received_requests().await.expect("requests recorded");
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(
        request.headers.get("authorization").unwrap(),
        "Bearer test-key"
    );
    let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(body["name"], "demo");
    let public_key = body["ssh_public_key"].as_str().unwrap();
    let key_regex = regex::Regex::new(r"^ssh-ed25519\s+[A-Za-z0-9+/=]+(\s+.*)?$").unwrap();
    assert!(
        key_regex.is_match(public_key),
        "ssh_public_key {public_key:?} must match the server validation pattern"
    );
}

#[tokio::test]
async fn create_omits_name_when_not_given() {
    let server = MockServer::start().await;
    mock_create(
        &server,
        ResponseTemplate::new(200).set_body_json(shell_json("sbx-1", "running")),
    )
    .await;

    Sandbox::create(create_options(&server))
        .await
        .expect("create succeeds")
        .detach();

    let requests = server.received_requests().await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert!(body.get("name").is_none());
    assert!(body.get("ssh_public_key").is_some());
}

#[tokio::test]
async fn quota_403s_map_to_quota_error() {
    for message in [
        "You've reached your plan's agent shell limit (1).",
        "Your plan does not include agent shells.",
    ] {
        let server = MockServer::start().await;
        mock_create(
            &server,
            ResponseTemplate::new(403).set_body_json(json!({ "message": message })),
        )
        .await;
        let err = create_error(&server).await;
        assert!(
            matches!(err, Error::Quota(_)),
            "{message:?} must map to Quota"
        );
        assert!(err.to_string().contains(message));
    }
}

#[tokio::test]
async fn auth_gates_map_to_auth_error() {
    let cases: Vec<(u16, serde_json::Value)> = vec![
        (401, json!({ "message": "Unauthenticated." })),
        (
            403,
            json!({ "message": "Agent shells are currently in limited preview." }),
        ),
        (
            403,
            json!({ "error": "verification_required", "message": "Verify to unlock." }),
        ),
        (
            403,
            json!({ "message": "Your account is on an abuse hold." }),
        ),
    ];
    for (status, body) in cases {
        let server = MockServer::start().await;
        mock_create(
            &server,
            ResponseTemplate::new(status).set_body_json(body.clone()),
        )
        .await;
        let err = create_error(&server).await;
        assert!(
            matches!(err, Error::Auth(_)),
            "HTTP {status} {body} must map to Auth, got {err:?}"
        );
    }
}

#[tokio::test]
async fn throttle_and_capacity_map_to_api_error() {
    for (status, message) in [
        (429u16, "Too Many Attempts."),
        (503u16, "No sandbox host capacity."),
    ] {
        let server = MockServer::start().await;
        mock_create(
            &server,
            ResponseTemplate::new(status).set_body_json(json!({ "message": message })),
        )
        .await;
        match create_error(&server).await {
            Error::Api { status: got, body } => {
                assert_eq!(got, status);
                assert!(body.contains(message));
            }
            other => panic!("HTTP {status} must map to Api, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn blank_api_key_is_auth_error_without_any_request() {
    let err = Sandbox::list(ListOptions::default().api_key("   "))
        .await
        .expect_err("blank key must fail");
    assert!(matches!(err, Error::Auth(_)));
    assert!(err.to_string().contains("XSHELLZ_API_KEY"));
}

#[tokio::test]
async fn list_parses_bare_top_level_array() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/shells/agent"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            shell_json("sbx-1", "running"),
            shell_json("sbx-2", "stopped"),
        ])))
        .mount(&server)
        .await;

    let sandboxes = Sandbox::list(
        ListOptions::default()
            .api_key("test-key")
            .api_url(format!("{}/v1", server.uri())),
    )
    .await
    .expect("list succeeds");

    assert_eq!(sandboxes.len(), 2);
    assert_eq!(sandboxes[0].uuid, "sbx-1");
    assert_eq!(sandboxes[1].status, "stopped");
    assert!(sandboxes[0].gvisor);
}

#[tokio::test]
async fn connect_resolves_uuid_via_list() {
    let server = MockServer::start().await;
    mock_create(
        &server,
        ResponseTemplate::new(200).set_body_json(shell_json("sbx-1", "running")),
    )
    .await;
    Mock::given(method("GET"))
        .and(path("/v1/shells/agent"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            shell_json("sbx-other", "running"),
            shell_json("sbx-1", "running"),
        ])))
        .mount(&server)
        .await;

    // Create first (against the mock) to obtain a real private key PEM.
    let created = Sandbox::create(create_options(&server)).await.unwrap();
    created.detach();
    let private_key = created.private_key_openssh().unwrap();

    let attached = Sandbox::connect(
        "sbx-1",
        &private_key,
        ConnectOptions::default()
            .api_key("test-key")
            .api_url(format!("{}/v1", server.uri())),
    )
    .await
    .expect("connect succeeds");
    attached.detach();

    assert_eq!(attached.uuid(), "sbx-1");
    assert_eq!(
        attached.private_key_openssh().as_deref(),
        Some(private_key.as_str())
    );
}

#[tokio::test]
async fn connect_unknown_uuid_is_not_running_error() {
    let server = MockServer::start().await;
    mock_create(
        &server,
        ResponseTemplate::new(200).set_body_json(shell_json("sbx-1", "running")),
    )
    .await;
    Mock::given(method("GET"))
        .and(path("/v1/shells/agent"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let created = Sandbox::create(create_options(&server)).await.unwrap();
    created.detach();
    let private_key = created.private_key_openssh().unwrap();

    let err = Sandbox::connect(
        "sbx-missing",
        &private_key,
        ConnectOptions::default()
            .api_key("test-key")
            .api_url(format!("{}/v1", server.uri())),
    )
    .await
    .expect_err("unknown uuid must fail");
    assert!(matches!(err, Error::NotRunning(_)));
    assert!(err.to_string().contains("sbx-missing"));
}

#[tokio::test]
async fn kill_deletes_and_is_idempotent() {
    let server = MockServer::start().await;
    mock_create(
        &server,
        ResponseTemplate::new(200).set_body_json(shell_json("sbx-1", "running")),
    )
    .await;
    Mock::given(method("DELETE"))
        .and(path("/v1/shells/agent/sbx-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "deleted": true })))
        .expect(1)
        .mount(&server)
        .await;

    let sandbox = Sandbox::create(create_options(&server)).await.unwrap();
    sandbox.kill().await.expect("kill succeeds");
    sandbox.kill().await.expect("second kill is a no-op");
    // MockServer verifies expect(1) on drop.
}

#[tokio::test]
async fn kill_swallows_404() {
    let server = MockServer::start().await;
    mock_create(
        &server,
        ResponseTemplate::new(200).set_body_json(shell_json("sbx-1", "running")),
    )
    .await;
    Mock::given(method("DELETE"))
        .and(path("/v1/shells/agent/sbx-1"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({ "message": "Not found." })))
        .mount(&server)
        .await;

    let sandbox = Sandbox::create(create_options(&server)).await.unwrap();
    sandbox.kill().await.expect("404 on kill is swallowed");
}

#[tokio::test]
async fn start_resumes_a_stopped_box() {
    let server = MockServer::start().await;
    mock_create(
        &server,
        ResponseTemplate::new(200).set_body_json(shell_json("sbx-1", "stopped")),
    )
    .await;
    Mock::given(method("POST"))
        .and(path("/v1/shells/agent/sbx-1/start"))
        .respond_with(ResponseTemplate::new(200).set_body_json(shell_json("sbx-1", "running")))
        .mount(&server)
        .await;

    let sandbox = Sandbox::create(create_options(&server)).await.unwrap();
    sandbox.detach();
    assert_eq!(sandbox.status(), "stopped");
    sandbox.start().await.expect("start succeeds");
    assert_eq!(sandbox.status(), "running");
}

#[tokio::test]
async fn start_404_is_not_running_error() {
    let server = MockServer::start().await;
    mock_create(
        &server,
        ResponseTemplate::new(200).set_body_json(shell_json("sbx-1", "running")),
    )
    .await;
    Mock::given(method("POST"))
        .and(path("/v1/shells/agent/sbx-1/start"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({ "message": "Stopped agent shell not found." })),
        )
        .mount(&server)
        .await;

    let sandbox = Sandbox::create(create_options(&server)).await.unwrap();
    sandbox.detach();
    let err = sandbox.start().await.expect_err("start must fail");
    assert!(matches!(err, Error::NotRunning(_)));
    assert!(err.to_string().contains("sbx-1"));
}

#[tokio::test]
async fn refresh_updates_state_from_the_list_endpoint() {
    let server = MockServer::start().await;
    mock_create(
        &server,
        ResponseTemplate::new(200).set_body_json(shell_json("sbx-1", "running")),
    )
    .await;
    Mock::given(method("GET"))
        .and(path("/v1/shells/agent"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!([shell_json("sbx-1", "stopped")])),
        )
        .mount(&server)
        .await;

    let sandbox = Sandbox::create(create_options(&server)).await.unwrap();
    sandbox.detach();
    let info = sandbox.refresh().await.expect("refresh succeeds");
    assert_eq!(info.status, "stopped");
    assert_eq!(sandbox.status(), "stopped");
}

async fn mock_list(server: &MockServer, shells: serde_json::Value) {
    Mock::given(method("GET"))
        .and(path("/v1/shells/agent"))
        .respond_with(ResponseTemplate::new(200).set_body_json(shells))
        .mount(server)
        .await;
}

fn get_or_create_options(server: &MockServer) -> GetOrCreateOptions {
    GetOrCreateOptions::default()
        .api_key("test-key")
        .api_url(format!("{}/v1", server.uri()))
}

/// Generate a real private-key PEM by creating a sandbox against a throwaway
/// mock (the SDK's keys module is private).
async fn generate_pem() -> String {
    let server = MockServer::start().await;
    mock_create(
        &server,
        ResponseTemplate::new(200).set_body_json(shell_json("sbx-keygen", "running")),
    )
    .await;
    let sandbox = Sandbox::create(create_options(&server)).await.unwrap();
    sandbox.detach();
    sandbox.private_key_openssh().unwrap()
}

#[tokio::test]
async fn get_or_create_creates_and_persists_key_to_keystore() {
    let server = MockServer::start().await;
    mock_list(&server, json!([])).await;
    mock_create(
        &server,
        ResponseTemplate::new(200).set_body_json(shell_json("sbx-1", "running")),
    )
    .await;

    let keystore = tempfile::tempdir().unwrap();
    let sandbox = Sandbox::get_or_create(
        "demo",
        get_or_create_options(&server).keystore_dir(keystore.path()),
    )
    .await
    .expect("get_or_create creates");
    sandbox.detach();

    assert_eq!(sandbox.uuid(), "sbx-1");
    let key_file = keystore.path().join("demo.key");
    assert_eq!(
        std::fs::read_to_string(&key_file).expect("key persisted"),
        sandbox.private_key_openssh().unwrap()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&key_file).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "persisted key must be 0600");
    }
}

#[tokio::test]
async fn get_or_create_attaches_to_existing_box_via_keystore() {
    let pem = generate_pem().await;
    let server = MockServer::start().await;
    mock_list(&server, json!([shell_json("sbx-1", "running")])).await;

    let keystore = tempfile::tempdir().unwrap();
    std::fs::write(keystore.path().join("demo.key"), &pem).unwrap();

    let sandbox = Sandbox::get_or_create(
        "demo",
        get_or_create_options(&server).keystore_dir(keystore.path()),
    )
    .await
    .expect("get_or_create attaches");
    sandbox.detach();

    assert_eq!(sandbox.uuid(), "sbx-1");
    assert_eq!(sandbox.private_key_openssh().as_deref(), Some(pem.as_str()));
    let requests = server.received_requests().await.unwrap();
    assert!(
        requests.iter().all(|r| r.method.as_str() == "GET"),
        "attach path must not POST a new box"
    );
}

#[tokio::test]
async fn get_or_create_starts_a_stopped_box() {
    let pem = generate_pem().await;
    let server = MockServer::start().await;
    mock_list(&server, json!([shell_json("sbx-1", "stopped")])).await;
    Mock::given(method("POST"))
        .and(path("/v1/shells/agent/sbx-1/start"))
        .respond_with(ResponseTemplate::new(200).set_body_json(shell_json("sbx-1", "running")))
        .expect(1)
        .mount(&server)
        .await;

    let keystore = tempfile::tempdir().unwrap();
    std::fs::write(keystore.path().join("demo.key"), &pem).unwrap();

    let sandbox = Sandbox::get_or_create(
        "demo",
        get_or_create_options(&server).keystore_dir(keystore.path()),
    )
    .await
    .expect("get_or_create starts the stopped box");
    sandbox.detach();
    assert_eq!(sandbox.status(), "running");
}

#[tokio::test]
async fn get_or_create_without_a_key_is_missing_key_error() {
    let server = MockServer::start().await;
    mock_list(&server, json!([shell_json("sbx-1", "running")])).await;

    let keystore = tempfile::tempdir().unwrap();
    let err = Sandbox::get_or_create(
        "demo",
        get_or_create_options(&server).keystore_dir(keystore.path()),
    )
    .await
    .expect_err("no key anywhere must fail");
    assert!(matches!(err, Error::MissingKey(_)));
    assert!(err.to_string().contains("demo.key"), "err: {err}");
}

#[tokio::test]
async fn get_or_create_with_keystore_disabled_is_missing_key_error() {
    let server = MockServer::start().await;
    mock_list(&server, json!([shell_json("sbx-1", "running")])).await;

    let err = Sandbox::get_or_create("demo", get_or_create_options(&server).no_keystore())
        .await
        .expect_err("disabled keystore + existing box must fail");
    assert!(matches!(err, Error::MissingKey(_)));
    assert!(err.to_string().contains("private_key"));
}

#[tokio::test]
async fn get_or_create_explicit_private_key_wins_over_keystore() {
    let pem = generate_pem().await;
    let server = MockServer::start().await;
    mock_list(&server, json!([shell_json("sbx-1", "running")])).await;

    let keystore = tempfile::tempdir().unwrap();
    std::fs::write(keystore.path().join("demo.key"), "garbage, not a key").unwrap();

    let sandbox = Sandbox::get_or_create(
        "demo",
        get_or_create_options(&server)
            .keystore_dir(keystore.path())
            .private_key(&pem),
    )
    .await
    .expect("explicit key wins over the (garbage) keystore file");
    sandbox.detach();
    assert_eq!(sandbox.private_key_openssh().as_deref(), Some(pem.as_str()));
}

#[tokio::test]
async fn get_or_create_with_keystore_disabled_still_creates() {
    let server = MockServer::start().await;
    mock_list(&server, json!([])).await;
    mock_create(
        &server,
        ResponseTemplate::new(200).set_body_json(shell_json("sbx-1", "running")),
    )
    .await;

    let sandbox = Sandbox::get_or_create("demo", get_or_create_options(&server).no_keystore())
        .await
        .expect("create-only path works without a keystore");
    sandbox.detach();
    assert!(sandbox.private_key_openssh().is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn get_or_create_returns_detached_box_that_survives_drop() {
    // A permanent named box must NOT be destroyed on drop: no DELETE mock is
    // registered, so any fire-and-forget DELETE would be an unmatched request.
    let server = MockServer::start().await;
    mock_list(&server, json!([])).await;
    mock_create(
        &server,
        ResponseTemplate::new(200).set_body_json(shell_json("sbx-1", "running")),
    )
    .await;

    let keystore = tempfile::tempdir().unwrap();
    let sandbox = Sandbox::get_or_create(
        "demo",
        get_or_create_options(&server).keystore_dir(keystore.path()),
    )
    .await
    .expect("get_or_create creates");
    drop(sandbox);

    // Give any (erroneous) fire-and-forget DELETE time to land, then assert
    // none was ever sent.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let requests = server.received_requests().await.unwrap_or_default();
    assert!(
        requests.iter().all(|r| r.method.as_str() != "DELETE"),
        "get_or_create box must be detached - drop must not DELETE it"
    );
}

fn boxfile_options(server: &MockServer) -> BoxfileOptions {
    BoxfileOptions::default()
        .api_key("test-key")
        .api_url(format!("{}/v1", server.uri()))
}

#[tokio::test]
async fn get_boxfile_returns_manifest_or_none() {
    for (manifest, expected) in [
        (json!("apt: jq ripgrep"), Some("apt: jq ripgrep")),
        (json!(null), None),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/shells/agent/boxfile"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "manifest": manifest })))
            .mount(&server)
            .await;
        let got = Sandbox::get_boxfile(boxfile_options(&server))
            .await
            .unwrap();
        assert_eq!(got.as_deref(), expected);
    }
}

#[tokio::test]
async fn set_boxfile_puts_manifest_and_returns_stored_value() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/v1/shells/agent/boxfile"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "manifest": "apt: jq" })))
        .mount(&server)
        .await;

    let stored = Sandbox::set_boxfile(Some("apt: jq"), boxfile_options(&server))
        .await
        .unwrap();
    assert_eq!(stored.as_deref(), Some("apt: jq"));

    let requests = server.received_requests().await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(body, json!({ "manifest": "apt: jq" }));
}

#[tokio::test]
async fn set_boxfile_none_clears_the_manifest() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/v1/shells/agent/boxfile"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "manifest": null })))
        .mount(&server)
        .await;

    let stored = Sandbox::set_boxfile(None, boxfile_options(&server))
        .await
        .unwrap();
    assert_eq!(stored, None);

    let requests = server.received_requests().await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(body, json!({ "manifest": null }));
}

#[tokio::test]
async fn stats_maps_the_wire_fields() {
    let server = MockServer::start().await;
    mock_create(
        &server,
        ResponseTemplate::new(200).set_body_json(shell_json("sbx-1", "running")),
    )
    .await;
    Mock::given(method("GET"))
        .and(path("/v1/shells/agent/sbx-1/stats"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "mem_used_mb": 210,
            "mem_limit_mb": 1024,
            "mem_allowed_mb": 1024,
            "cpu_percent": 12.5,
            "cpu_allowed_vcpus": 1.0,
            "cpu_throttled_periods": 3,
            "pids_current": 24,
            "pids_allowed": 256,
            "disk_used_mb": 512,
            "disk_allowed_mb": 5120,
            "net_rx_mb": 10.2,
            "net_tx_mb": 1.4,
            "blk_read_mb": 30,
            "blk_write_mb": 12
        })))
        .mount(&server)
        .await;

    let sandbox = Sandbox::create(create_options(&server)).await.unwrap();
    sandbox.detach();
    let stats = sandbox.stats().await.expect("stats succeed");
    assert_eq!(stats.mem_used_mb, 210.0);
    assert_eq!(stats.mem_allowed_mb, 1024.0);
    assert_eq!(stats.cpu_percent, 12.5);
    assert_eq!(stats.cpu_allowed_vcpus, 1.0);
    assert_eq!(stats.cpu_throttled_periods, 3);
    assert_eq!(stats.pids_current, 24);
    assert_eq!(stats.pids_allowed, 256);
    assert_eq!(stats.disk_used_mb, 512.0);
    assert_eq!(stats.net_rx_mb, 10.2);
    assert_eq!(stats.blk_write_mb, 12.0);
}

#[tokio::test]
async fn procs_maps_the_wire_fields() {
    let server = MockServer::start().await;
    mock_create(
        &server,
        ResponseTemplate::new(200).set_body_json(shell_json("sbx-1", "running")),
    )
    .await;
    Mock::given(method("GET"))
        .and(path("/v1/shells/agent/sbx-1/procs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "procs": [
                { "pid": 42, "comm": "node", "cpu": 1.5, "mem": 2.0 },
                { "pid": 43, "comm": "claude", "cpu": 12.0, "mem": 8.5 }
            ],
            "sessions": 2,
            "agents": ["claude"],
            "disk_used_mb": 100,
            "disk_allowed_mb": 5120
        })))
        .mount(&server)
        .await;

    let sandbox = Sandbox::create(create_options(&server)).await.unwrap();
    sandbox.detach();
    let procs = sandbox.procs().await.expect("procs succeed");
    assert_eq!(procs.procs.len(), 2);
    assert_eq!(procs.procs[1].comm, "claude");
    assert_eq!(procs.sessions, 2);
    assert_eq!(procs.agents, vec!["claude"]);
    assert_eq!(procs.disk_allowed_mb, 5120.0);
}

#[tokio::test]
async fn restart_reboots_and_refreshes_state() {
    let server = MockServer::start().await;
    mock_create(
        &server,
        ResponseTemplate::new(200).set_body_json(shell_json("sbx-1", "running")),
    )
    .await;
    let mut rebooted = shell_json("sbx-1", "running");
    rebooted["ssh_port"] = json!(42002);
    Mock::given(method("POST"))
        .and(path("/v1/shells/agent/sbx-1/restart"))
        .respond_with(ResponseTemplate::new(200).set_body_json(rebooted))
        .expect(1)
        .mount(&server)
        .await;

    let sandbox = Sandbox::create(create_options(&server)).await.unwrap();
    sandbox.detach();
    sandbox.restart().await.expect("restart succeeds");
    assert_eq!(sandbox.ssh_port(), Some(42002));
}

#[tokio::test]
async fn terminal_url_returns_the_signed_url() {
    let server = MockServer::start().await;
    mock_create(
        &server,
        ResponseTemplate::new(200).set_body_json(shell_json("sbx-1", "running")),
    )
    .await;
    Mock::given(method("GET"))
        .and(path("/v1/shells/agent/sbx-1/terminal"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(
                json!({ "url": "https://shellus1.xshellz.com/terminal/sbx-1?tok=abc" }),
            ),
        )
        .mount(&server)
        .await;

    let sandbox = Sandbox::create(create_options(&server)).await.unwrap();
    sandbox.detach();
    assert_eq!(
        sandbox.terminal_url().await.expect("terminal_url succeeds"),
        "https://shellus1.xshellz.com/terminal/sbx-1?tok=abc"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn drop_fires_best_effort_delete() {
    let server = MockServer::start().await;
    mock_create(
        &server,
        ResponseTemplate::new(200).set_body_json(shell_json("sbx-1", "running")),
    )
    .await;
    Mock::given(method("DELETE"))
        .and(path("/v1/shells/agent/sbx-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "deleted": true })))
        .expect(1)
        .mount(&server)
        .await;

    let sandbox = Sandbox::create(create_options(&server)).await.unwrap();
    drop(sandbox);

    // The Drop DELETE is fire-and-forget on the runtime; give it a moment.
    for _ in 0..50 {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let requests = server.received_requests().await.unwrap_or_default();
        if requests.iter().any(|r| r.method.as_str() == "DELETE") {
            return;
        }
    }
    panic!("Drop did not fire a best-effort DELETE within 5s");
}
