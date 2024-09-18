use near_account_id::AccountId;
use near_crypto::InMemorySigner;
use crate::rpc_client::{fetch_pending_requests, respond};
use crate::ecdsa::{generate_response};

pub async fn process_signature_requests(
    rpc_client: &near_fetch::Client,
    mpc_contract_id: &AccountId,
    signer: &InMemorySigner,
    sign_sk: &k256::SecretKey,
) -> anyhow::Result<()> {
    let requests = fetch_pending_requests(rpc_client, mpc_contract_id).await?;
    if requests.len() > 0 {
        tracing::info!("fetched {} pending requests: {:#?}", requests.len(), requests);
    }

    for request in requests.iter() {
        let response = generate_response(&request, sign_sk).await;
        respond(rpc_client, signer, mpc_contract_id, &request, &response).await?;
    }
    // wait 5 seconds after processing requests
    if requests.len() > 0 {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }

    Ok(())
}

pub async fn run(
    rpc_client: &near_fetch::Client,
    mpc_contract_id: &AccountId,
    signer: &InMemorySigner,
    sign_sk: &k256::SecretKey,
) -> anyhow::Result<()> {
    tracing::debug!("running a test node");

    loop {
        process_signature_requests(rpc_client, mpc_contract_id, signer, sign_sk).await?;

        // wait 1 sec before next query
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}
