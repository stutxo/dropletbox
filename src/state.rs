use std::str::FromStr;

use boltz_client::{
    bitcoin::{
        self, PublicKey,
        key::rand::thread_rng,
        secp256k1::{Keypair, SecretKey as BtcSecretKey},
    },
    boltz::{CreateReverseResponse, Leaf, SwapTree},
    elements::{
        self,
        hex::{FromHex, ToHex},
    },
    network::{Chain, LiquidChain, Network},
    swaps::SwapScript,
    util::secrets::Preimage,
};
use lightning_invoice::Bolt11Invoice;
use serde::{Deserialize, Serialize};
use wasm_bindgen::JsValue;

use crate::liquid_inscription::{InscriptionSpec, InscriptionWallet, PreparedReveal};

pub(crate) const APP_SNAPSHOT_VERSION: u32 = 3;
pub(crate) const BOLTZ_MAINNET_URL: &str = "https://api.boltz.exchange/v2";
pub(crate) const LIQUID_ESPLORA_URL: &str = "https://blockstream.info/liquid/api";
pub(crate) const POLL_INTERVAL_MS: u32 = 10_000;
pub(crate) const MINIMUM_FINAL_OUTPUT_SAT: u64 = 1;
pub(crate) const FALLBACK_UPLOAD_CONTENT_TYPE: &str = "text/plain;charset=utf-8";
pub(crate) const FALLBACK_UPLOAD_PAYLOAD: &str = "\u{1F4A7}";
pub(crate) const MAX_UPLOAD_BYTES: usize = 390_000;

#[derive(Clone)]
pub(crate) struct SessionWallet {
    pub(crate) claim_keys: Keypair,
    inscription_wallet: InscriptionWallet,
}

impl SessionWallet {
    pub(crate) fn generate(
        config: &SwapConfig,
        inscription_spec: &InscriptionSpec,
    ) -> Result<Self, String> {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let mut rng = thread_rng();

        Ok(Self {
            claim_keys: Keypair::new(&secp, &mut rng),
            inscription_wallet: InscriptionWallet::generate(config.liquid_chain, inscription_spec)?,
        })
    }

    pub(crate) fn claim_public_key(&self) -> PublicKey {
        PublicKey::new(self.claim_keys.public_key())
    }

    pub(crate) fn commit_address_string(&self) -> String {
        self.inscription_wallet.commit_address_string()
    }

    pub(crate) fn commit_address(&self) -> &elements::Address {
        self.inscription_wallet.commit_address()
    }

    pub(crate) fn inscription_wallet(&self) -> &InscriptionWallet {
        &self.inscription_wallet
    }

    pub(crate) fn snapshot(&self) -> SessionWalletSnapshot {
        SessionWalletSnapshot {
            claim_secret_key_hex: self.claim_keys.display_secret().to_string(),
            inscription_secret_key_hex: self.inscription_wallet.inscription_secret_key_string(),
            commit_blinding_secret_key_hex: self
                .inscription_wallet
                .commit_blinding_secret_key_string(),
        }
    }

    pub(crate) fn restore(
        config: &SwapConfig,
        inscription_spec: &InscriptionSpec,
        snapshot: SessionWalletSnapshot,
    ) -> Result<Self, String> {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let claim_secret_key = BtcSecretKey::from_str(&snapshot.claim_secret_key_hex)
            .map_err(|err| err.to_string())?;

        Ok(Self {
            claim_keys: Keypair::from_secret_key(&secp, &claim_secret_key),
            inscription_wallet: InscriptionWallet::restore(
                config.liquid_chain,
                inscription_spec,
                &snapshot.inscription_secret_key_hex,
                &snapshot.commit_blinding_secret_key_hex,
            )?,
        })
    }

    pub(crate) fn rebuild_for_spec(
        &self,
        config: &SwapConfig,
        inscription_spec: &InscriptionSpec,
    ) -> Result<Self, String> {
        Self::restore(config, inscription_spec, self.snapshot())
    }
}

#[derive(Clone)]
pub(crate) struct SwapConfig {
    pub(crate) network: Network,
    pub(crate) chain: Chain,
    pub(crate) liquid_chain: LiquidChain,
    pub(crate) from_asset: &'static str,
    pub(crate) to_asset: &'static str,
    pub(crate) minimum_final_output_sat: u64,
    pub(crate) poll_interval_ms: u32,
    pub(crate) boltz_api_url: &'static str,
    pub(crate) liquid_esplora_url: &'static str,
}

impl SwapConfig {
    pub(crate) fn mainnet() -> Self {
        Self {
            network: Network::Mainnet,
            chain: Chain::Liquid(LiquidChain::Liquid),
            liquid_chain: LiquidChain::Liquid,
            from_asset: "BTC",
            to_asset: "L-BTC",
            minimum_final_output_sat: MINIMUM_FINAL_OUTPUT_SAT,
            poll_interval_ms: POLL_INTERVAL_MS,
            boltz_api_url: BOLTZ_MAINNET_URL,
            liquid_esplora_url: LIQUID_ESPLORA_URL,
        }
    }
}

#[derive(Clone)]
pub(crate) struct PreparedSwapTransactions {
    pub(crate) commit_tx: elements::Transaction,
    pub(crate) commit_txid: String,
    pub(crate) reveal: PreparedReveal,
    pub(crate) commit_broadcasted: bool,
    pub(crate) reveal_broadcasted: bool,
}

impl PreparedSwapTransactions {
    pub(crate) fn snapshot(&self) -> PreparedSwapTransactionsSnapshot {
        PreparedSwapTransactionsSnapshot {
            commit_tx_hex: liquid_tx_to_hex(&self.commit_tx),
            commit_txid: self.commit_txid.clone(),
            reveal: PreparedRevealSnapshot {
                tx_hex: liquid_tx_to_hex(&self.reveal.tx),
                txid: self.reveal.txid.clone(),
                fee_sat: self.reveal.fee_sat,
                output_amount_sat: self.reveal.output_amount_sat,
                target_prefix_hex: self.reveal.target_prefix_hex.clone(),
                grind_nonce: self.reveal.grind_nonce,
            },
            commit_broadcasted: self.commit_broadcasted,
            reveal_broadcasted: self.reveal_broadcasted,
        }
    }

    pub(crate) fn restore(snapshot: PreparedSwapTransactionsSnapshot) -> Result<Self, String> {
        let commit_tx = liquid_tx_from_hex(&snapshot.commit_tx_hex)?;
        let computed_commit_txid = commit_tx.txid().to_string();
        if computed_commit_txid != snapshot.commit_txid {
            return Err(format!(
                "Snapshot commit txid {} does not match decoded transaction {}.",
                snapshot.commit_txid, computed_commit_txid
            ));
        }

        let reveal_tx = liquid_tx_from_hex(&snapshot.reveal.tx_hex)?;
        let computed_reveal_txid = reveal_tx.txid().to_string();
        if computed_reveal_txid != snapshot.reveal.txid {
            return Err(format!(
                "Snapshot reveal txid {} does not match decoded transaction {}.",
                snapshot.reveal.txid, computed_reveal_txid
            ));
        }

        Ok(Self {
            commit_tx,
            commit_txid: snapshot.commit_txid,
            reveal: PreparedReveal {
                tx: reveal_tx,
                txid: snapshot.reveal.txid,
                fee_sat: snapshot.reveal.fee_sat,
                output_amount_sat: snapshot.reveal.output_amount_sat,
                target_prefix_hex: snapshot.reveal.target_prefix_hex,
                grind_nonce: snapshot.reveal.grind_nonce,
            },
            commit_broadcasted: snapshot.commit_broadcasted,
            reveal_broadcasted: snapshot.reveal_broadcasted,
        })
    }
}

#[derive(Clone)]
pub(crate) struct ActiveReverseSwap {
    pub(crate) preimage: Preimage,
    pub(crate) swap_id: String,
    pub(crate) display: SwapDisplayDetails,
    pub(crate) upload: UploadState,
    pub(crate) reverse_response: CreateReverseResponse,
    pub(crate) swap_script: SwapScript,
    pub(crate) last_status: Option<String>,
    pub(crate) last_lockup_txid: Option<String>,
    pub(crate) prepared: Option<PreparedSwapTransactions>,
    pub(crate) terminal_error: Option<String>,
}

impl ActiveReverseSwap {
    pub(crate) fn snapshot(&self) -> Result<ActiveReverseSwapSnapshot, String> {
        let preimage_hex = self
            .preimage
            .bytes
            .ok_or_else(|| "Active reverse swap is missing preimage bytes.".to_owned())?
            .to_hex();

        Ok(ActiveReverseSwapSnapshot {
            preimage_hex,
            swap_id: self.swap_id.clone(),
            display: self.display.clone(),
            upload: Some(self.upload.snapshot()),
            reverse_response: ReverseResponseSnapshot::from_reverse_response(
                &self.reverse_response,
            ),
            last_status: self.last_status.clone(),
            last_lockup_txid: self.last_lockup_txid.clone(),
            prepared: self
                .prepared
                .as_ref()
                .map(PreparedSwapTransactions::snapshot),
            terminal_error: self.terminal_error.clone(),
        })
    }

    pub(crate) fn restore(
        config: &SwapConfig,
        wallet: &SessionWallet,
        snapshot: ActiveReverseSwapSnapshot,
        upload: UploadState,
    ) -> Result<Self, String> {
        let mut display = snapshot.display;
        display.hydrate_invoice_timing();
        let preimage = Preimage::from_str(&snapshot.preimage_hex).map_err(|err| err.to_string())?;
        let claim_public_key = wallet.claim_public_key();
        let reverse_response = snapshot
            .reverse_response
            .restore(snapshot.swap_id.clone(), display.invoice.clone())?;
        reverse_response
            .validate(&preimage, &claim_public_key, config.chain)
            .map_err(|err| err.to_string())?;
        let swap_script =
            SwapScript::reverse_from_swap_resp(config.chain, &reverse_response, claim_public_key)
                .map_err(|err| err.to_string())?;

        Ok(Self {
            preimage,
            swap_id: snapshot.swap_id,
            display,
            upload,
            reverse_response,
            swap_script,
            last_status: snapshot.last_status,
            last_lockup_txid: snapshot.last_lockup_txid,
            prepared: snapshot
                .prepared
                .map(PreparedSwapTransactions::restore)
                .transpose()?,
            terminal_error: snapshot.terminal_error,
        })
    }
}

pub(crate) struct AppState {
    pub(crate) config: SwapConfig,
    pub(crate) liquid_genesis_hash: Option<elements::BlockHash>,
    pub(crate) current_upload: UploadState,
    pub(crate) inscription_spec: InscriptionSpec,
    pub(crate) wallet: SessionWallet,
    pub(crate) active_swap: Option<ActiveReverseSwap>,
}

impl AppState {
    pub(crate) fn snapshot(&self) -> Result<AppSnapshot, String> {
        Ok(AppSnapshot {
            version: APP_SNAPSHOT_VERSION,
            wallet: self.wallet.snapshot(),
            current_upload: Some(self.current_upload.snapshot()),
            active_swap: self
                .active_swap
                .as_ref()
                .map(ActiveReverseSwap::snapshot)
                .transpose()?,
        })
    }

    pub(crate) fn restore(snapshot: AppSnapshot) -> Result<Self, String> {
        if snapshot.version != APP_SNAPSHOT_VERSION {
            return Err(format!(
                "Unsupported snapshot version {}. Expected {}.",
                snapshot.version, APP_SNAPSHOT_VERSION
            ));
        }

        let config = SwapConfig::mainnet();
        let active_swap_upload = snapshot
            .active_swap
            .as_ref()
            .and_then(|active| active.upload.clone())
            .map(UploadState::restore)
            .transpose()?;
        let snapshot_upload = snapshot
            .current_upload
            .map(UploadState::restore)
            .transpose()?;
        let current_upload = active_swap_upload
            .clone()
            .or(snapshot_upload)
            .unwrap_or_else(UploadState::fallback);
        let inscription_spec = current_upload.to_inscription_spec()?;
        let wallet = SessionWallet::restore(&config, &inscription_spec, snapshot.wallet)?;
        let active_swap = snapshot
            .active_swap
            .map(|active| {
                ActiveReverseSwap::restore(
                    &config,
                    &wallet,
                    active,
                    active_swap_upload
                        .clone()
                        .unwrap_or_else(|| current_upload.clone()),
                )
            })
            .transpose()?;

        Ok(Self {
            config,
            liquid_genesis_hash: None,
            current_upload,
            inscription_spec,
            wallet,
            active_swap,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WalletView {
    pub(crate) network: String,
    pub(crate) commit_address: String,
    pub(crate) destination_address: String,
    pub(crate) minimum_final_output_sat: u64,
    pub(crate) poll_interval_ms: u32,
    pub(crate) reveal_target_prefix_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SwapDisplayDetails {
    pub(crate) invoice_amount_sat: u64,
    pub(crate) invoice: String,
    #[serde(default)]
    pub(crate) invoice_created_at_unix: Option<u64>,
    #[serde(default)]
    pub(crate) invoice_expires_at_unix: Option<u64>,
    #[serde(default)]
    pub(crate) invoice_expiry_secs: Option<u64>,
    pub(crate) commit_address: String,
    pub(crate) destination_address: String,
    pub(crate) reveal_target_prefix_hex: String,
    pub(crate) expected_lockup_sat: u64,
    pub(crate) expected_commit_sat: u64,
    pub(crate) expected_receive_sat: u64,
    pub(crate) boltz_fee_sat: u64,
    pub(crate) claim_fee_sat: u64,
    pub(crate) reveal_fee_sat: u64,
    pub(crate) lockup_fee_sat: u64,
}

impl SwapDisplayDetails {
    pub(crate) fn hydrate_invoice_timing(&mut self) {
        if self.invoice_created_at_unix.is_some() && self.invoice_expiry_secs.is_some() {
            return;
        }

        if let Ok(timing) = invoice_timing_from_bolt11(&self.invoice) {
            self.invoice_created_at_unix = Some(timing.created_at_unix);
            self.invoice_expires_at_unix = timing.expires_at_unix;
            self.invoice_expiry_secs = Some(timing.expiry_secs);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UiSwapStatusView {
    pub(crate) phase: String,
    pub(crate) raw_status: Option<String>,
    pub(crate) message: String,
    pub(crate) is_terminal: bool,
    pub(crate) swap_id: Option<String>,
    pub(crate) commit_broadcasted: bool,
    pub(crate) commit_txid: Option<String>,
    pub(crate) commit_tx_hex: Option<String>,
    pub(crate) reveal_broadcasted: bool,
    pub(crate) reveal_txid: Option<String>,
    pub(crate) reveal_tx_hex: Option<String>,
    pub(crate) lockup_txid: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CreatedSwapView {
    pub(crate) swap_id: String,
    pub(crate) invoice_amount_sat: u64,
    pub(crate) invoice: String,
    pub(crate) invoice_created_at_unix: Option<u64>,
    pub(crate) invoice_expires_at_unix: Option<u64>,
    pub(crate) invoice_expiry_secs: Option<u64>,
    pub(crate) commit_address: String,
    pub(crate) destination_address: String,
    pub(crate) reveal_target_prefix_hex: String,
    pub(crate) expected_lockup_sat: u64,
    pub(crate) expected_commit_sat: u64,
    pub(crate) expected_receive_sat: u64,
    pub(crate) boltz_fee_sat: u64,
    pub(crate) claim_fee_sat: u64,
    pub(crate) reveal_fee_sat: u64,
    pub(crate) lockup_fee_sat: u64,
    pub(crate) status: UiSwapStatusView,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct QuoteInvoiceView {
    pub(crate) invoice_amount_sat: u64,
    pub(crate) destination_address: String,
    pub(crate) expected_lockup_sat: u64,
    pub(crate) expected_commit_sat: u64,
    pub(crate) expected_receive_sat: u64,
    pub(crate) boltz_fee_sat: u64,
    pub(crate) claim_fee_sat: u64,
    pub(crate) reveal_fee_sat: u64,
    pub(crate) lockup_fee_sat: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UploadState {
    pub(crate) file_name: Option<String>,
    pub(crate) content_type: String,
    pub(crate) payload: Vec<u8>,
    pub(crate) is_fallback: bool,
}

impl UploadState {
    pub(crate) fn fallback() -> Self {
        Self {
            file_name: None,
            content_type: FALLBACK_UPLOAD_CONTENT_TYPE.to_owned(),
            payload: FALLBACK_UPLOAD_PAYLOAD.as_bytes().to_vec(),
            is_fallback: true,
        }
    }

    fn validate(&self) -> Result<(), String> {
        if self.content_type.trim().is_empty() {
            return Err("Upload content type cannot be empty.".to_owned());
        }
        if self.payload.len() > MAX_UPLOAD_BYTES {
            return Err(format!(
                "Upload exceeds the {} byte limit.",
                MAX_UPLOAD_BYTES
            ));
        }

        Ok(())
    }

    pub(crate) fn to_inscription_spec(&self) -> Result<InscriptionSpec, String> {
        self.validate()?;
        InscriptionSpec::mainnet_with_payload(
            self.payload.clone(),
            self.content_type.as_bytes().to_vec(),
        )
    }

    pub(crate) fn snapshot(&self) -> UploadStateSnapshot {
        UploadStateSnapshot {
            file_name: self.file_name.clone(),
            content_type: self.content_type.clone(),
            payload_hex: self.payload.to_hex(),
            is_fallback: self.is_fallback,
        }
    }

    pub(crate) fn restore(snapshot: UploadStateSnapshot) -> Result<Self, String> {
        let upload = Self {
            file_name: snapshot.file_name,
            content_type: snapshot.content_type,
            payload: Vec::<u8>::from_hex(&snapshot.payload_hex).map_err(|err| err.to_string())?,
            is_fallback: snapshot.is_fallback,
        };
        upload.validate()?;
        Ok(upload)
    }

    pub(crate) fn view(&self) -> UploadView {
        UploadView {
            file_name: self.file_name.clone(),
            content_type: self.content_type.clone(),
            payload_len: self.payload.len(),
            is_fallback: self.is_fallback,
        }
    }

    pub(crate) fn preview_view(&self) -> UploadPreviewView {
        UploadPreviewView {
            file_name: self.file_name.clone(),
            content_type: self.content_type.clone(),
            payload_len: self.payload.len(),
            payload_hex: self.payload.to_hex(),
            is_fallback: self.is_fallback,
            text: String::from_utf8(self.payload.clone()).ok(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UploadView {
    pub(crate) file_name: Option<String>,
    pub(crate) content_type: String,
    pub(crate) payload_len: usize,
    pub(crate) is_fallback: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UploadPreviewView {
    pub(crate) file_name: Option<String>,
    pub(crate) content_type: String,
    pub(crate) payload_len: usize,
    pub(crate) payload_hex: String,
    pub(crate) is_fallback: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) text: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AppSnapshot {
    pub(crate) version: u32,
    pub(crate) wallet: SessionWalletSnapshot,
    #[serde(default)]
    pub(crate) current_upload: Option<UploadStateSnapshot>,
    pub(crate) active_swap: Option<ActiveReverseSwapSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SessionWalletSnapshot {
    pub(crate) claim_secret_key_hex: String,
    pub(crate) inscription_secret_key_hex: String,
    pub(crate) commit_blinding_secret_key_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ActiveReverseSwapSnapshot {
    pub(crate) preimage_hex: String,
    pub(crate) swap_id: String,
    pub(crate) display: SwapDisplayDetails,
    #[serde(default)]
    pub(crate) upload: Option<UploadStateSnapshot>,
    pub(crate) reverse_response: ReverseResponseSnapshot,
    pub(crate) last_status: Option<String>,
    pub(crate) last_lockup_txid: Option<String>,
    pub(crate) prepared: Option<PreparedSwapTransactionsSnapshot>,
    pub(crate) terminal_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UploadStateSnapshot {
    pub(crate) file_name: Option<String>,
    pub(crate) content_type: String,
    pub(crate) payload_hex: String,
    pub(crate) is_fallback: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReverseResponseSnapshot {
    claim_leaf_output_hex: String,
    claim_leaf_version: u8,
    refund_leaf_output_hex: String,
    refund_leaf_version: u8,
    lockup_address: String,
    refund_public_key: String,
    timeout_block_height: u32,
    onchain_amount: u64,
    blinding_key: Option<String>,
}

impl ReverseResponseSnapshot {
    pub(crate) fn from_reverse_response(response: &CreateReverseResponse) -> Self {
        Self {
            claim_leaf_output_hex: response.swap_tree.claim_leaf.output.clone(),
            claim_leaf_version: response.swap_tree.claim_leaf.version,
            refund_leaf_output_hex: response.swap_tree.refund_leaf.output.clone(),
            refund_leaf_version: response.swap_tree.refund_leaf.version,
            lockup_address: response.lockup_address.clone(),
            refund_public_key: response.refund_public_key.to_string(),
            timeout_block_height: response.timeout_block_height,
            onchain_amount: response.onchain_amount,
            blinding_key: response.blinding_key.clone(),
        }
    }

    pub(crate) fn restore(
        self,
        swap_id: String,
        _invoice: String,
    ) -> Result<CreateReverseResponse, String> {
        let refund_public_key =
            PublicKey::from_str(&self.refund_public_key).map_err(|err| err.to_string())?;

        Ok(CreateReverseResponse {
            id: swap_id,
            invoice: None,
            swap_tree: SwapTree {
                claim_leaf: Leaf {
                    output: self.claim_leaf_output_hex,
                    version: self.claim_leaf_version,
                },
                refund_leaf: Leaf {
                    output: self.refund_leaf_output_hex,
                    version: self.refund_leaf_version,
                },
            },
            lockup_address: self.lockup_address,
            refund_public_key,
            timeout_block_height: self.timeout_block_height,
            onchain_amount: self.onchain_amount,
            blinding_key: self.blinding_key,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PreparedSwapTransactionsSnapshot {
    pub(crate) commit_tx_hex: String,
    pub(crate) commit_txid: String,
    pub(crate) reveal: PreparedRevealSnapshot,
    pub(crate) commit_broadcasted: bool,
    pub(crate) reveal_broadcasted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PreparedRevealSnapshot {
    pub(crate) tx_hex: String,
    pub(crate) txid: String,
    pub(crate) fee_sat: u64,
    pub(crate) output_amount_sat: u64,
    pub(crate) target_prefix_hex: String,
    pub(crate) grind_nonce: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CreateInvoiceRequest {
    #[serde(default)]
    pub(crate) destination_address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SetUploadRequest {
    #[serde(default)]
    pub(crate) file_name: Option<String>,
    #[serde(default)]
    pub(crate) content_type: Option<String>,
    #[serde(default)]
    pub(crate) payload_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InvoiceTiming {
    pub(crate) created_at_unix: u64,
    pub(crate) expires_at_unix: Option<u64>,
    pub(crate) expiry_secs: u64,
}

pub(crate) fn new_app_state() -> Result<AppState, String> {
    let config = SwapConfig::mainnet();
    let current_upload = UploadState::fallback();
    let inscription_spec = current_upload.to_inscription_spec()?;
    let wallet = SessionWallet::generate(&config, &inscription_spec)?;

    Ok(AppState {
        config,
        liquid_genesis_hash: None,
        current_upload,
        inscription_spec,
        wallet,
        active_swap: None,
    })
}

pub(crate) fn created_swap_view(
    swap_id: &str,
    display: &SwapDisplayDetails,
    status: UiSwapStatusView,
) -> CreatedSwapView {
    CreatedSwapView {
        swap_id: swap_id.to_owned(),
        invoice_amount_sat: display.invoice_amount_sat,
        invoice: display.invoice.clone(),
        invoice_created_at_unix: display.invoice_created_at_unix,
        invoice_expires_at_unix: display.invoice_expires_at_unix,
        invoice_expiry_secs: display.invoice_expiry_secs,
        commit_address: display.commit_address.clone(),
        destination_address: display.destination_address.clone(),
        reveal_target_prefix_hex: display.reveal_target_prefix_hex.clone(),
        expected_lockup_sat: display.expected_lockup_sat,
        expected_commit_sat: display.expected_commit_sat,
        expected_receive_sat: display.expected_receive_sat,
        boltz_fee_sat: display.boltz_fee_sat,
        claim_fee_sat: display.claim_fee_sat,
        reveal_fee_sat: display.reveal_fee_sat,
        lockup_fee_sat: display.lockup_fee_sat,
        status,
    }
}

pub(crate) fn network_label(network: Network) -> &'static str {
    match network {
        Network::Mainnet => "mainnet",
        Network::Testnet => "testnet",
        Network::Regtest => "regtest",
    }
}

pub(crate) fn invoice_timing_from_bolt11(invoice: &str) -> Result<InvoiceTiming, String> {
    let invoice = Bolt11Invoice::from_str(invoice)
        .map_err(|err| format!("Boltz returned an invalid BOLT11 invoice: {err}"))?;

    Ok(InvoiceTiming {
        created_at_unix: invoice.duration_since_epoch().as_secs(),
        expires_at_unix: invoice.expires_at().map(|duration| duration.as_secs()),
        expiry_secs: invoice.expiry_time().as_secs(),
    })
}

pub(crate) fn to_js_value<T: Serialize>(value: &T) -> Result<JsValue, JsValue> {
    serde_wasm_bindgen::to_value(value).map_err(|err| js_err(err.to_string()))
}

pub(crate) fn js_err(message: impl Into<String>) -> JsValue {
    JsValue::from_str(&message.into())
}

pub(crate) fn liquid_tx_to_hex(tx: &elements::Transaction) -> String {
    elements::encode::serialize(tx).to_hex()
}

pub(crate) fn liquid_tx_from_hex(hex: &str) -> Result<elements::Transaction, String> {
    let bytes = Vec::<u8>::from_hex(hex).map_err(|err| err.to_string())?;
    elements::encode::deserialize(&bytes).map_err(|err| err.to_string())
}
