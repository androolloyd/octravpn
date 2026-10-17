//! Exercise the actual mesh CLI and the same persistent wire redeemer across
//! crashes, rather than constructing a parallel test-only admin assembly.
use octravpn_mesh::{
    tailscale_wire::{MachineRecord, MachineRegistrationStore, PreauthRedeemer, RedeemError},
    MachineRegistry,
};
use octravpn_node::mesh_store::MeshStore;
use serde_json::{json, Value};
use std::{
    path::Path,
    process::{Child, Command, Stdio},
    sync::Arc,
    time::Duration,
};

const TOKEN: &str = "mesh-enrollment-test-only";
struct Daemon(Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn launch(directory: &Path, address: &str) -> Daemon {
    Daemon(
        Command::new(env!("CARGO_BIN_EXE_octravpn-node"))
            .args(["mesh", "serve", "--listen", address, "--state-dir"])
            .arg(directory)
            .args(["--admin-token", TOKEN])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    )
}
fn launch_config(directory: &Path, address: &str) -> Daemon {
    let parent = directory.parent().unwrap();
    let token = parent.join("admin.token");
    std::fs::write(&token, TOKEN).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let config = parent.join("mesh.json");
    std::fs::write(
        &config,
        serde_json::to_vec(&json!({
            "state_dir":"wire", "admin_token_file":"admin.token", "http_addr":address,
            "dns":{"base_domain":"octranet.test", "override_local_dns":false}
        }))
        .unwrap(),
    )
    .unwrap();
    Daemon(
        Command::new(env!("CARGO_BIN_EXE_octravpn-node"))
            .args(["mesh", "run", "--service-config"])
            .arg(config)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    )
}
async fn ready(http: &reqwest::Client, base: &str) {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if http
                .get(format!("{base}/key?v=113"))
                .send()
                .await
                .is_ok_and(|r| r.status().is_success())
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    })
    .await
    .expect("mesh CLI did not start");
}
async fn keys(http: &reqwest::Client, base: &str) -> Vec<Value> {
    http.get(format!("{base}/api/v1/preauthkeys"))
        .bearer_auth(TOKEN)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap()
}

#[tokio::test]
async fn cli_admin_and_wire_enrollment_share_durable_keys_and_revocation() {
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().join("wire");
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let address = format!("127.0.0.1:{port}");
    let base = format!("http://{address}");
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let daemon = launch(&state, &address);
    ready(&http, &base).await;
    assert_eq!(
        http.post(format!("{base}/admin/preauth"))
            .bearer_auth(TOKEN)
            .json(&json!({"user":"alice","ttl_secs":"invalid"}))
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::BAD_REQUEST
    );
    assert!(keys(&http, &base).await.is_empty());
    let mut rejection = None;
    for auth in [None, Some("wrong-token")] {
        let request = http.post(format!("{base}/admin/preauth"));
        let response = match auth {
            Some(token) => request.bearer_auth(token),
            None => request,
        }
        .send()
        .await
        .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
        let body = response.bytes().await.unwrap();
        if let Some(previous) = &rejection {
            assert_eq!(&body, previous);
        }
        rejection = Some(body);
    }
    let default: Value = http
        .post(format!("{base}/admin/preauth"))
        .bearer_auth(TOKEN)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(default["user"], "default");
    let reusable: Value = http
        .post(format!("{base}/admin/preauth"))
        .bearer_auth(TOKEN)
        .json(&json!({"user":"alice","ttl_secs":123,"reusable":true}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!((120..=123).contains(&(reusable["expires_at"].as_u64().unwrap() - now)));
    let single: Value = http
        .post(format!("{base}/api/v1/preauthkeys"))
        .bearer_auth(TOKEN)
        .json(&json!({"user":"alice","ttl_secs":300}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let initial = keys(&http, &base).await;
    let reusable_id = initial
        .iter()
        .find(|row| row["key"] == reusable["key"])
        .unwrap()["id"]
        .clone();
    let policy = "// durable operator ACL\n{\"acls\":[],}";
    assert_eq!(
        http.put(format!("{base}/api/v1/policy"))
            .bearer_auth(TOKEN)
            .body(policy)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::OK
    );
    let api_key: Value = http
        .post(format!("{base}/api/v1/apikey"))
        .bearer_auth(TOKEN)
        .json(&json!({}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let api_token = api_key["api_key"].as_str().unwrap();
    assert_eq!(
        http.get(format!("{base}/api/v1/users"))
            .bearer_auth(api_token)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::OK
    );
    assert_eq!(
        http.get(format!("{base}/admin/"))
            .bearer_auth(api_token)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::NOT_FOUND
    );
    drop(daemon); // An abrupt exit must not reset credential use or expiry.

    let store = MeshStore::open(&state, Arc::new(MachineRegistry::new()))
        .await
        .unwrap();
    let token = single["key"].as_str().unwrap();
    let (a, b) = tokio::join!(store.preauth.redeem(token), store.preauth.redeem(token));
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    let admitted = a.or(b).unwrap();
    let node_key = "11".repeat(32);
    let registration = store
        .machines
        .create_or_update_auth_key_registration(
            MachineRecord::new_at(
                chrono::Utc::now(),
                node_key.clone(),
                "22".repeat(32),
                admitted.user,
                "test-mac".into(),
                "100.64.0.2".parse().unwrap(),
                false,
            ),
            &octravpn_mesh::policy::PolicyStore::new(),
            admitted.auth_key_id,
        )
        .await
        .unwrap();
    assert_eq!(registration.record.user, "alice");
    assert_eq!(
        store
            .preauth
            .redeem(reusable["key"].as_str().unwrap())
            .await
            .unwrap()
            .user,
        "alice"
    );
    drop(store);

    let daemon = launch_config(&state, &address);
    ready(&http, &base).await;
    let restored_policy: Value = http
        .get(format!("{base}/api/v1/policy"))
        .bearer_auth(api_token)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(restored_policy["loaded"], true);
    assert_eq!(restored_policy["raw"], policy);
    assert_eq!(
        http.put(format!("{base}/api/v1/policy"))
            .bearer_auth(api_token)
            .body("invalid")
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::BAD_REQUEST
    );
    let api_rows: Value = http
        .get(format!("{base}/api/v1/apikey"))
        .bearer_auth(api_token)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let api_rows = api_rows["api_keys"].as_array().unwrap();
    assert_eq!(api_rows.len(), 1);
    assert_eq!(
        http.post(format!("{base}/api/v1/apikey/expire"))
            .bearer_auth(TOKEN)
            .json(&json!({"id":api_rows[0]["id"]}))
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::NO_CONTENT
    );
    assert_eq!(
        http.get(format!("{base}/api/v1/users"))
            .bearer_auth(api_token)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::NOT_FOUND
    );
    let restored = keys(&http, &base).await;
    let row = restored
        .iter()
        .find(|row| row["id"] == reusable_id)
        .unwrap();
    let mut expire = reqwest::Url::parse(&format!("{base}/api/v1/preauthkeys/")).unwrap();
    expire
        .path_segments_mut()
        .unwrap()
        .pop_if_empty()
        .push(row["key"].as_str().unwrap())
        .push("expire");
    assert_eq!(
        http.post(expire)
            .bearer_auth(TOKEN)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::NO_CONTENT
    );
    let users: Vec<Value> = http
        .get(format!("{base}/api/v1/users"))
        .bearer_auth(TOKEN)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(users.iter().any(|user| user["name"] == "alice"));
    assert!(users.iter().any(|user| user["name"] == "default"));
    let machines: Vec<Value> = http
        .get(format!("{base}/api/v1/machines"))
        .bearer_auth(TOKEN)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(machines.iter().any(|machine| machine["name"] == "test-mac"));
    drop(daemon);

    let daemon = launch(&state, &address);
    ready(&http, &base).await;
    assert_eq!(
        http.get(format!("{base}/api/v1/users"))
            .bearer_auth(api_token)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::NOT_FOUND
    );
    drop(daemon);
    let store = MeshStore::open(&state, Arc::new(MachineRegistry::new()))
        .await
        .unwrap();
    assert!(matches!(
        store.preauth.redeem(token).await,
        Err(RedeemError::AlreadyUsed)
    ));
    assert!(matches!(
        store
            .preauth
            .redeem(reusable["key"].as_str().unwrap())
            .await,
        Err(RedeemError::Expired)
    ));
    for entry in std::fs::read_dir(&state).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            let bytes = std::fs::read(path).unwrap();
            for secret in [
                &single["key"],
                &reusable["key"],
                &default["key"],
                &api_key["api_key"],
            ] {
                let secret = secret.as_str().unwrap().as_bytes();
                assert!(!bytes.windows(secret.len()).any(|window| window == secret));
            }
        }
    }
}

#[tokio::test]
async fn configured_knock_without_a_valid_psk_refuses_startup() {
    for psk in [None, Some("invalid-psk")] {
        let temp = tempfile::tempdir().unwrap();
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_octravpn-node"));
        command
            .args(["mesh", "serve", "--listen", "127.0.0.1:0", "--state-dir"])
            .arg(temp.path())
            .env("OCTRAVPN_KNOCK_ENABLED", "1")
            .env_remove("OCTRAVPN_KNOCK_PSK")
            .kill_on_drop(true);
        if let Some(psk) = psk {
            command.env("OCTRAVPN_KNOCK_PSK", psk);
        }
        let result = tokio::time::timeout(Duration::from_secs(5), command.output())
            .await
            .unwrap()
            .unwrap();
        assert!(!result.status.success());
        assert!(String::from_utf8(result.stderr).unwrap().contains("knock"));
    }
}
