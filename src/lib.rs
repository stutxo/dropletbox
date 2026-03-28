mod liquid_inscription;
mod state;
mod swap;

use std::cell::RefCell;

use liquid_inscription::{
    DecodedRevealPayload, decode_reveal_payload as decode_reveal_payload_from_tx,
};
use state::*;
use swap::*;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct DropletboxApp {
    state: RefCell<AppState>,
}

#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

#[wasm_bindgen(js_name = decodeRevealPayload)]
pub fn decode_reveal_payload(tx_hex: &str) -> Result<JsValue, JsValue> {
    let tx = liquid_tx_from_hex(tx_hex).map_err(js_err)?;
    let decoded: DecodedRevealPayload = decode_reveal_payload_from_tx(&tx).map_err(js_err)?;
    to_js_value(&decoded)
}

impl DropletboxApp {
    fn ensure_upload_is_mutable(&self) -> Result<(), String> {
        let state = self.state.borrow();
        if let Some(active) = state.active_swap.as_ref()
            && !active_swap_is_finished(active)
        {
            return Err(
                "A swap is already active. Create a new droplet after it finishes.".to_owned(),
            );
        }

        Ok(())
    }

    fn replace_current_upload(&self, upload: UploadState) -> Result<UploadView, String> {
        let mut state = self.state.borrow_mut();
        let inscription_spec = upload.to_inscription_spec()?;
        let wallet = state
            .wallet
            .rebuild_for_spec(&state.config, &inscription_spec)
            .map_err(|err| err.to_string())?;
        state.current_upload = upload.clone();
        state.inscription_spec = inscription_spec;
        state.wallet = wallet;
        Ok(upload.view())
    }

    fn apply_upload_request(&self, request: SetUploadRequest) -> Result<UploadView, String> {
        self.ensure_upload_is_mutable()?;
        let upload = UploadState {
            file_name: request.file_name,
            content_type: request
                .content_type
                .filter(|content_type| !content_type.trim().is_empty())
                .unwrap_or_else(|| FALLBACK_UPLOAD_CONTENT_TYPE.to_owned()),
            payload: request.payload_bytes,
            is_fallback: false,
        };
        self.replace_current_upload(upload)
    }

    async fn liquid_genesis_hash(&self) -> Result<boltz_client::elements::BlockHash, JsValue> {
        if let Some(genesis_hash) = self.state.borrow().liquid_genesis_hash {
            return Ok(genesis_hash);
        }

        let config = self.state.borrow().config.clone();
        let genesis_hash = fetch_liquid_genesis_hash(&config).await?;
        self.state.borrow_mut().liquid_genesis_hash = Some(genesis_hash);
        Ok(genesis_hash)
    }
}

#[wasm_bindgen]
impl DropletboxApp {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<DropletboxApp, JsValue> {
        Ok(Self {
            state: RefCell::new(new_app_state().map_err(js_err)?),
        })
    }

    #[wasm_bindgen(js_name = fromSnapshot)]
    pub fn from_snapshot(snapshot: JsValue) -> Result<DropletboxApp, JsValue> {
        let snapshot =
            serde_wasm_bindgen::from_value(snapshot).map_err(|err| js_err(err.to_string()))?;
        Ok(Self {
            state: RefCell::new(AppState::restore(snapshot).map_err(js_err)?),
        })
    }

    pub fn wallet(&self) -> Result<JsValue, JsValue> {
        let state = self.state.borrow();
        let wallet_view = WalletView {
            network: network_label(state.config.network).to_owned(),
            commit_address: state.wallet.commit_address_string(),
            destination_address: state.inscription_spec.destination_address_string(),
            minimum_final_output_sat: state.config.minimum_final_output_sat,
            poll_interval_ms: state.config.poll_interval_ms,
            reveal_target_prefix_hex: state.inscription_spec.reveal_target_prefix_hex(),
        };
        to_js_value(&wallet_view)
    }

    #[wasm_bindgen(js_name = currentUpload)]
    pub fn current_upload(&self) -> Result<JsValue, JsValue> {
        let state = self.state.borrow();
        to_js_value(&state.current_upload.view())
    }

    #[wasm_bindgen(js_name = currentUploadPreview)]
    pub fn current_upload_preview(&self) -> Result<JsValue, JsValue> {
        let state = self.state.borrow();
        to_js_value(&state.current_upload.preview_view())
    }

    #[wasm_bindgen(js_name = currentSwap)]
    pub fn current_swap(&self) -> Result<JsValue, JsValue> {
        let state = self.state.borrow();
        let current_swap = state.active_swap.as_ref().map(|active_swap| {
            created_swap_view(
                &active_swap.swap_id,
                &active_swap.display,
                build_status_view(
                    Some(active_swap.swap_id.as_str()),
                    active_swap.last_status.as_deref(),
                    active_swap.last_lockup_txid.as_deref(),
                    active_swap.prepared.as_ref(),
                    active_swap.terminal_error.as_deref(),
                    None,
                ),
            )
        });
        to_js_value(&current_swap)
    }

    #[wasm_bindgen(js_name = quoteInvoice)]
    pub async fn quote_invoice(&self, request: JsValue) -> Result<JsValue, JsValue> {
        let (config, inscription_spec, wallet, request) = {
            let state = self.state.borrow();
            (
                state.config.clone(),
                state.inscription_spec.clone(),
                state.wallet.clone(),
                parse_create_invoice_request(request)?,
            )
        };
        let genesis_hash = self.liquid_genesis_hash().await?;
        let quote =
            compute_invoice_quote(&config, &inscription_spec, &wallet, genesis_hash, request)
                .await?;

        to_js_value(&QuoteInvoiceView {
            invoice_amount_sat: quote.invoice_amount_sat,
            destination_address: quote.destination_address.to_string(),
            expected_lockup_sat: quote.expected_lockup_sat,
            expected_commit_sat: quote.expected_commit_sat,
            expected_receive_sat: quote.expected_receive_sat,
            boltz_fee_sat: quote.boltz_fee_sat,
            claim_fee_sat: quote.claim_fee_sat,
            reveal_fee_sat: quote.reveal_fee_sat,
            lockup_fee_sat: quote.lockup_fee_sat,
        })
    }

    #[wasm_bindgen(js_name = exportSnapshot)]
    pub fn export_snapshot(&self) -> Result<JsValue, JsValue> {
        let snapshot = self.state.borrow().snapshot().map_err(js_err)?;
        to_js_value(&snapshot)
    }

    #[wasm_bindgen(js_name = setUpload)]
    pub fn set_upload(&self, request: JsValue) -> Result<JsValue, JsValue> {
        let request = parse_set_upload_request(request)?;
        let view = self.apply_upload_request(request).map_err(js_err)?;
        to_js_value(&view)
    }

    #[wasm_bindgen(js_name = clearUpload)]
    pub fn clear_upload(&self) -> Result<JsValue, JsValue> {
        self.ensure_upload_is_mutable().map_err(js_err)?;
        let view = self
            .replace_current_upload(UploadState::fallback())
            .map_err(js_err)?;
        to_js_value(&view)
    }

    #[wasm_bindgen(js_name = retryPendingSwap)]
    pub async fn retry_pending_swap(&self) -> Result<JsValue, JsValue> {
        let (config, wallet, active_swap) = {
            let state = self.state.borrow();
            let Some(active_swap) = state.active_swap.clone() else {
                return Err(js_err("No active swap to retry."));
            };
            (state.config.clone(), state.wallet.clone(), active_swap)
        };
        let genesis_hash = self.liquid_genesis_hash().await?;
        let outcome =
            swap::retry_pending_swap(&config, &wallet, &active_swap, genesis_hash).await?;

        if let Some(state_active) = self.state.borrow_mut().active_swap.as_mut()
            && state_active.swap_id == active_swap.swap_id
        {
            state_active.prepared = outcome.prepared.clone();
            state_active.terminal_error = None;
        }

        let status = build_status_view(
            Some(active_swap.swap_id.as_str()),
            active_swap.last_status.as_deref(),
            active_swap.last_lockup_txid.as_deref(),
            outcome.prepared.as_ref(),
            None,
            Some(outcome.message),
        );
        let created = created_swap_view(&active_swap.swap_id, &active_swap.display, status);
        to_js_value(&created)
    }

    pub async fn create_invoice(&self, request: JsValue) -> Result<JsValue, JsValue> {
        let (config, inscription_spec, wallet, current_upload, request) = {
            let state = self.state.borrow();
            if let Some(active) = state.active_swap.as_ref()
                && !active_swap_is_finished(active)
            {
                return Err(js_err(
                    "A swap is already active. Wait for it to finish first.",
                ));
            }

            (
                state.config.clone(),
                state.inscription_spec.clone(),
                state.wallet.clone(),
                state.current_upload.clone(),
                parse_create_invoice_request(request)?,
            )
        };
        let genesis_hash = self.liquid_genesis_hash().await?;
        let created = create_reverse_swap(
            &config,
            &inscription_spec,
            &wallet,
            &current_upload,
            genesis_hash,
            request,
        )
        .await?;

        self.state.borrow_mut().active_swap = Some(created.active_swap);
        to_js_value(&created.view)
    }

    pub async fn poll_once(&self) -> Result<JsValue, JsValue> {
        let (config, wallet, active_swap) = {
            let state = self.state.borrow();
            let Some(active_swap) = state.active_swap.clone() else {
                return to_js_value(&build_status_view(
                    None,
                    None,
                    None,
                    None,
                    None,
                    Some("No active swap. Create an invoice to start.".to_owned()),
                ));
            };
            (state.config.clone(), state.wallet.clone(), active_swap)
        };
        let genesis_hash = self.liquid_genesis_hash().await?;
        let outcome = poll_active_swap(&config, &wallet, &active_swap, genesis_hash).await?;

        if let Some(update) = outcome.state_update
            && let Some(state_active) = self.state.borrow_mut().active_swap.as_mut()
            && state_active.swap_id == active_swap.swap_id
        {
            state_active.last_status = Some(update.raw_status);
            state_active.last_lockup_txid = update.effective_lockup_txid;
            state_active.prepared = update.prepared;
            state_active.terminal_error = update.terminal_error;
        }

        to_js_value(&outcome.status_view)
    }
}

fn parse_set_upload_request(request: JsValue) -> Result<SetUploadRequest, JsValue> {
    if request.is_undefined() || request.is_null() {
        return Err(js_err("Upload payload is required."));
    }

    serde_wasm_bindgen::from_value(request).map_err(|err| js_err(err.to_string()))
}

fn parse_create_invoice_request(request: JsValue) -> Result<CreateInvoiceRequest, JsValue> {
    if request.is_undefined() || request.is_null() {
        Ok(CreateInvoiceRequest {
            destination_address: None,
        })
    } else {
        serde_wasm_bindgen::from_value(request).map_err(|err| js_err(err.to_string()))
    }
}

#[cfg(test)]
mod tests;
