use near_account_id::AccountId;
use near_crypto::InMemorySigner;
use mpc_contract::primitives::SignatureRequest;
use crypto_shared::types::SignatureResponse;

use serde_json::json;

pub async fn fetch_pending_requests(
    rpc_client: &near_fetch::Client,
    mpc_contract_id: &AccountId,
) -> anyhow::Result<Vec<SignatureRequest>> {
    let requests: Vec<SignatureRequest> = rpc_client
        .view(mpc_contract_id, "get_pending_requests")
        .args_json(json!({}))
        .await
        .map_err(|e| {
            tracing::warn!(%e, "failed to fetch mpc pending requests");
            e
        })?
        .json()?;
    tracing::debug!("pending requests: {:#?}", requests);
    Ok(requests)
}

pub async fn respond(
    rpc_client: &near_fetch::Client,
    signer: &InMemorySigner,
    mpc_contract_id: &AccountId,
    request: &SignatureRequest,
    response: &SignatureResponse,
) -> anyhow::Result<()> {
    tracing::info!("{} responds to sign request {:?} with response {:?}", signer.account_id, request, response);
    let result = rpc_client
        .call(signer, mpc_contract_id, "respond")
        .args_json(json!({
            "request": request,
            "response": response
        }))
        .max_gas()
        .retry_exponential(10, 5)
        .transact()
        .await
        .map_err(|e| {
            tracing::warn!(%e, "failed to respond to sign request");
            e
        })?
        .json()?;

    Ok(result)
}
