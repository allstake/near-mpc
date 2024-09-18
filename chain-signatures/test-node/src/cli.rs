use clap::Parser;
use near_account_id::AccountId;
use near_crypto::{InMemorySigner, SecretKey};
use tracing_subscriber::{layer::SubscriberExt, EnvFilter, Registry};
use k256::elliptic_curve::sec1::ToEncodedPoint;

use crate::worker;

#[derive(Parser, Debug)]
pub enum Cli {
    Start {
        /// NEAR RPC address
        #[arg(
            long,
            env("MPC_NEAR_RPC"),
            default_value("https://rpc.testnet.pagoda.co")
        )]
        near_rpc: String,
        /// MPC contract id
        #[arg(long, env("MPC_CONTRACT_ID"), default_value("v1.signer-dev.testnet"))]
        mpc_contract_id: AccountId,
        /// This node's account id
        #[arg(long, env("MPC_ACCOUNT_ID"))]
        account_id: AccountId,
        /// This node's account ed25519 secret key
        #[arg(long, env("MPC_ACCOUNT_SK"))]
        account_sk: SecretKey,
        /// The secp256k1 secret key used to sign messages on behalf of mocked MPC
        #[arg(long, env("MPC_SIGN_SK"))]
        sign_sk: String,
    },
}

impl Cli {
    pub fn into_str_args(self) -> Vec<String> {
        match self {
            Cli::Start {
                near_rpc,
                mpc_contract_id,
                account_id,
                account_sk,
                sign_sk,
            } => {
                let args = vec![
                    "start".to_string(),
                    "--near-rpc".to_string(),
                    near_rpc,
                    "--mpc-contract-id".to_string(),
                    mpc_contract_id.to_string(),
                    "--account-id".to_string(),
                    account_id.to_string(),
                    "--account-sk".to_string(),
                    account_sk.to_string(),
                    "--sign-sk".to_string(),
                    sign_sk,
                ];

                args
            }
        }
    }
}

pub fn run(cmd: Cli) -> anyhow::Result<()> {
    // Install global collector configured based on RUST_LOG env var.
    let base_subscriber = Registry::default().with(EnvFilter::from_default_env());

    let fmt_layer = tracing_subscriber::fmt::layer().with_thread_ids(true);
    let subscriber = base_subscriber.with(Some(fmt_layer));

    tracing::subscriber::set_global_default(subscriber).expect("Failed to set subscriber");

    let _span = tracing::trace_span!("cli").entered();

    match cmd {
        Cli::Start {
            near_rpc,
            mpc_contract_id,
            account_id,
            account_sk,
            sign_sk,
        } => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;

            let rpc_client = near_fetch::Client::new(&near_rpc);
            tracing::debug!(rpc_addr = rpc_client.rpc_addr(), "rpc client initialized");

            let signer = InMemorySigner::from_secret_key(account_id.clone(), account_sk);
            let sign_sk = k256::SecretKey::from_slice(&hex::decode(sign_sk).expect("Failed to parse sign private key")).unwrap();
            let sign_pk = near_crypto::PublicKey::SECP256K1(
                near_crypto::Secp256K1PublicKey::try_from(
                    &sign_sk.public_key().as_affine().to_encoded_point(false).as_bytes()[1..65],
                )
                .unwrap(),
            );
            tracing::info!("mpc public key: {:?}", sign_pk);

            rt.block_on(async {
                let worker_handle = tokio::spawn(async move {
                    worker::run(&rpc_client, &mpc_contract_id, &signer, &sign_sk).await
                });
                worker_handle.await??;
                tracing::debug!("spinning down");

                anyhow::Ok(())
            })?;
        }
    }

    Ok(())
}
