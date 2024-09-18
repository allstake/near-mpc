pub mod common;
use common::{create_response, init_env};
use mpc_contract::primitives::{SignRequest, SignatureRequest};

use near_sdk::{CurveType, NearToken, PublicKey};
use serde_json::json;
use std::str::FromStr;

#[tokio::test]
async fn test_view_key_version() -> anyhow::Result<()> {
    let (_, contract, _, _) = init_env().await;

    let version: u32 = contract
        .view("latest_key_version")
        .await
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(version, 0);
    Ok(())
}

#[tokio::test]
async fn test_view_public_key() -> anyhow::Result<()> {
    let (_, contract, _, _) = init_env().await;

    let key: String = contract.view("public_key").await.unwrap().json().unwrap();
    println!("{:?}", key);
    let pk = PublicKey::from_str(&key)?;
    assert_eq!(pk.curve_type(), CurveType::SECP256K1);
    Ok(())
}

#[tokio::test]
async fn test_view_derived_public_key() -> anyhow::Result<()> {
    let (_, contract, _, _) = init_env().await;

    let key: String = contract
        .view("derived_public_key")
        .args_json(json!({
            "path": "test",
            "predecessor": "alice.near"
        }))
        .await
        .unwrap()
        .json()
        .unwrap();
    let pk = PublicKey::from_str(&key)?;
    assert_eq!(pk.curve_type(), CurveType::SECP256K1);
    Ok(())
}

#[tokio::test]
async fn test_process_pending_requests() -> anyhow::Result<()> {
    let (worker, contract, _, sk) = init_env().await;

    let requests: Vec<SignatureRequest> = contract
        .view("get_pending_requests")
        .args_json(json!({}))
        .await
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(requests.len(), 0);

    let alice = worker.dev_create_account().await?;
    let path = "test";

    const REQUEST_COUNT: usize = 3;
    let mut sig_requests = Vec::with_capacity(REQUEST_COUNT);
    let mut sig_responses = Vec::with_capacity(REQUEST_COUNT);
    let mut tx_status = Vec::with_capacity(REQUEST_COUNT);

    for i in 1..REQUEST_COUNT + 1 {
        let msg = format!("hello world {}", i);
        println!("submitting: {msg}");
        let (payload_hash, respond_req, respond_resp) =
            create_response(alice.id(), &msg, path, &sk).await;
        let request = SignRequest {
            payload: payload_hash,
            path: path.into(),
            key_version: 0,
        };
        sig_requests.push(respond_req);
        sig_responses.push(respond_resp);

        let status = alice
            .call(contract.id(), "sign")
            .args_json(serde_json::json!({
                "request": request,
            }))
            .deposit(NearToken::from_near(1))
            .max_gas()
            .transact_async()
            .await?;
        tx_status.push(status);
    }

    // wait so all sign are called, but not yet timeout
    tokio::time::sleep(std::time::Duration::from_secs(10)).await;

    let requests: Vec<SignatureRequest> = contract
        .view("get_pending_requests")
        .args_json(json!({}))
        .await
        .unwrap()
        .json()
        .unwrap();
    println!("pending requests: {:#?}", requests);
    assert_eq!(requests.len(), REQUEST_COUNT);

    for i in 1..REQUEST_COUNT + 1 {
        // Call `respond` as if we are the MPC network itself.
        let respond_req = &sig_requests[i - 1];
        let respond_resp = &sig_responses[i - 1];
        let respond = contract
            .call("respond")
            .args_json(serde_json::json!({
                "request": respond_req,
                "response": respond_resp
            }))
            .max_gas()
            .transact()
            .await?;
        dbg!(&respond);
    }

    // wait so all responses are completed
    tokio::time::sleep(std::time::Duration::from_secs(10)).await;

    let requests: Vec<SignatureRequest> = contract
        .view("get_pending_requests")
        .args_json(json!({}))
        .await
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(requests.len(), 0);

    Ok(())
}
