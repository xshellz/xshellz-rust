//! Control-plane client tests against a local mock HTTP server.
//!
//! No real network: every test spins up a wiremock server and points the SDK
//! at it with an explicit `api_url`.

use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use xshellz::{ConnectOptions, CreateOptions, Error, ListOptions, Sandbox};

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
