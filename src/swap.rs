use std::str::FromStr;

use boltz_client::{
    boltz::{BoltzApiClientV2, CreateReverseRequest, ReversePair},
    elements,
    error::Error as BoltzClientError,
    fees::Fee,
    network::{LiquidClient, esplora::EsploraLiquidClient},
    swaps::{
        BtcLikeTransaction, ChainClient, SwapTransactionParams, TransactionOptions,
        fees::estimate_claim_fee,
    },
    util::secrets::Preimage,
};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_futures::JsFuture;

use crate::{
    liquid_inscription::{
        InscriptionSpec, RevealContext, RevealFeePolicy, parse_confidential_destination_address,
    },
    state::{
        ActiveReverseSwap, CreateInvoiceRequest, CreatedSwapView, PreparedSwapTransactions,
        SessionWallet, SwapConfig, SwapDisplayDetails, UiSwapStatusView, UploadState,
        created_swap_view, invoice_timing_from_bolt11, js_err, liquid_tx_to_hex,
    },
};

pub(crate) const LIQUID_CLIENT_TIMEOUT_SECS: u64 = 30;
pub(crate) const LIQUID_FEE_RATE_SAT_PER_VB: f64 = 0.01;
pub(crate) const LIQUID_MIN_RELAY_FEE_RATE_SAT_PER_VB: f64 = 0.1;
pub(crate) const LIQUID_RELAY_SAFETY_BUFFER_SAT: u64 = 1;
const MAX_LIQUID_FEE_CONVERGENCE_PASSES: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct FeePolicy {
    pub(crate) target_sat_per_vb: f64,
    pub(crate) relay_min_sat_per_vb: f64,
    pub(crate) safety_buffer_sat: u64,
    pub(crate) max_convergence_passes: usize,
}

impl FeePolicy {
    pub(crate) fn liquid_default() -> Self {
        Self {
            target_sat_per_vb: LIQUID_FEE_RATE_SAT_PER_VB,
            relay_min_sat_per_vb: LIQUID_MIN_RELAY_FEE_RATE_SAT_PER_VB,
            safety_buffer_sat: LIQUID_RELAY_SAFETY_BUFFER_SAT,
            max_convergence_passes: MAX_LIQUID_FEE_CONVERGENCE_PASSES,
        }
    }

    fn effective_sat_per_vb(&self) -> f64 {
        self.target_sat_per_vb.max(self.relay_min_sat_per_vb)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReverseSwapSizing {
    pub(crate) invoice_amount_sat: u64,
    pub(crate) required_lockup_sat: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct ComputedInvoiceQuote {
    pub(crate) invoice_amount_sat: u64,
    pub(crate) required_lockup_sat: u64,
    pub(crate) destination_address: elements::Address,
    pub(crate) expected_lockup_sat: u64,
    pub(crate) expected_commit_sat: u64,
    pub(crate) expected_receive_sat: u64,
    pub(crate) boltz_fee_sat: u64,
    pub(crate) claim_fee_sat: u64,
    pub(crate) reveal_fee_sat: u64,
    pub(crate) lockup_fee_sat: u64,
}

#[derive(Clone)]
pub(crate) struct RetrySwapOutcome {
    pub(crate) prepared: Option<PreparedSwapTransactions>,
    pub(crate) message: String,
}

pub(crate) struct CreatedReverseSwap {
    pub(crate) active_swap: ActiveReverseSwap,
    pub(crate) view: CreatedSwapView,
}

pub(crate) struct SwapPollOutcome {
    pub(crate) status_view: UiSwapStatusView,
    pub(crate) state_update: Option<SwapStateUpdate>,
}

pub(crate) struct SwapStateUpdate {
    pub(crate) raw_status: String,
    pub(crate) effective_lockup_txid: Option<String>,
    pub(crate) prepared: Option<PreparedSwapTransactions>,
    pub(crate) terminal_error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SwapProcessingStep {
    NoOp,
    WaitForLockup,
    PrepareTransactions,
    BroadcastCommit,
    BroadcastReveal,
}

struct CommitBuildContext<'a> {
    wallet: &'a SessionWallet,
    active_swap: &'a ActiveReverseSwap,
    boltz_client: &'a BoltzApiClientV2,
    chain_client: &'a ChainClient,
    lockup_tx: Option<BtcLikeTransaction>,
}

struct PrepareTransactionsContext<'a> {
    config: &'a SwapConfig,
    fee_policy: FeePolicy,
    inscription_spec: &'a InscriptionSpec,
    wallet: &'a SessionWallet,
    active_swap: &'a ActiveReverseSwap,
    boltz_client: &'a BoltzApiClientV2,
    genesis_hash: elements::BlockHash,
    lockup_tx: Option<BtcLikeTransaction>,
}

struct SwapProcessState {
    prepared: Option<PreparedSwapTransactions>,
    terminal_error: Option<String>,
    message_override: Option<String>,
}

struct SwapProcessContext<'a> {
    config: &'a SwapConfig,
    fee_policy: FeePolicy,
    wallet: &'a SessionWallet,
    active_swap: &'a ActiveReverseSwap,
    inscription_spec: &'a InscriptionSpec,
    boltz_client: &'a BoltzApiClientV2,
    genesis_hash: elements::BlockHash,
    raw_status: &'a str,
    lockup_tx: Option<BtcLikeTransaction>,
    effective_lockup_txid: Option<String>,
}

pub(crate) async fn fetch_liquid_genesis_hash(
    config: &SwapConfig,
) -> Result<elements::BlockHash, JsValue> {
    create_liquid_esplora_client(config)
        .get_genesis_hash()
        .await
        .map_err(|err| js_err(err.to_string()))
}

pub(crate) async fn compute_invoice_quote(
    config: &SwapConfig,
    inscription_spec: &InscriptionSpec,
    wallet: &SessionWallet,
    genesis_hash: elements::BlockHash,
    request: CreateInvoiceRequest,
) -> Result<ComputedInvoiceQuote, JsValue> {
    let requested_destination_address = request
        .destination_address
        .unwrap_or_else(|| inscription_spec.destination_address_string());
    let destination_address =
        parse_confidential_destination_address(&requested_destination_address).map_err(js_err)?;

    let boltz_client = create_boltz_client(config);
    let pair = reverse_pair(&boltz_client).await?;
    let fee_policy = FeePolicy::liquid_default();
    let claim_fee_sat = relay_adjusted_commit_fee_sat(config, fee_policy);
    let reveal_fee_sat = wallet
        .inscription_wallet()
        .estimate_reveal_fee_sats(
            config.liquid_chain,
            &destination_address,
            genesis_hash,
            fee_policy.target_sat_per_vb,
            fee_policy.relay_min_sat_per_vb,
        )
        .map_err(js_err)?;
    let sizing = minimum_reverse_invoice_amount(
        &pair,
        claim_fee_sat,
        reveal_fee_sat,
        config.minimum_final_output_sat,
    )
    .map_err(js_err)?;
    let lockup_fee_sat = pair.fees.lockup();
    let boltz_fee_sat = pair.fees.boltz(sizing.invoice_amount_sat);
    let expected_lockup_sat = sizing
        .invoice_amount_sat
        .checked_sub(boltz_fee_sat + lockup_fee_sat)
        .ok_or_else(|| js_err("Calculated Boltz lockup amount underflowed."))?;
    let expected_commit_sat = expected_lockup_sat
        .checked_sub(claim_fee_sat)
        .ok_or_else(|| js_err("Estimated claim fee leaves no commit output value."))?;
    let expected_receive_sat = expected_commit_sat
        .checked_sub(reveal_fee_sat)
        .ok_or_else(|| js_err("Estimated reveal fee leaves no final Liquid output value."))?;
    if expected_receive_sat == 0 {
        return Err(js_err(
            "Estimated reveal fee leaves a zero-valued final Liquid output.",
        ));
    }

    Ok(ComputedInvoiceQuote {
        invoice_amount_sat: sizing.invoice_amount_sat,
        required_lockup_sat: sizing.required_lockup_sat,
        destination_address,
        expected_lockup_sat,
        expected_commit_sat,
        expected_receive_sat,
        boltz_fee_sat,
        claim_fee_sat,
        reveal_fee_sat,
        lockup_fee_sat,
    })
}

pub(crate) async fn create_reverse_swap(
    config: &SwapConfig,
    inscription_spec: &InscriptionSpec,
    wallet: &SessionWallet,
    current_upload: &UploadState,
    genesis_hash: elements::BlockHash,
    request: CreateInvoiceRequest,
) -> Result<CreatedReverseSwap, JsValue> {
    let quote =
        compute_invoice_quote(config, inscription_spec, wallet, genesis_hash, request).await?;
    let boltz_client = create_boltz_client(config);
    let preimage = Preimage::random();
    let claim_public_key = wallet.claim_public_key();
    let request = CreateReverseRequest {
        from: config.from_asset.to_owned(),
        to: config.to_asset.to_owned(),
        claim_public_key,
        invoice: None,
        invoice_amount: Some(quote.invoice_amount_sat),
        preimage_hash: Some(preimage.sha256),
        description: None,
        description_hash: None,
        address: None,
        address_signature: None,
        referral_id: None,
        webhook: None,
    };

    let reverse_response = boltz_client
        .post_reverse_req(request)
        .await
        .map_err(|err| js_err(err.to_string()))?;
    reverse_response
        .validate(&preimage, &claim_public_key, config.chain)
        .map_err(|err| js_err(err.to_string()))?;

    let swap_script = boltz_client::swaps::SwapScript::reverse_from_swap_resp(
        config.chain,
        &reverse_response,
        claim_public_key,
    )
    .map_err(|err| js_err(err.to_string()))?;

    let invoice = reverse_response
        .invoice
        .clone()
        .ok_or_else(|| js_err("Boltz did not return an invoice."))?;
    let invoice_timing = invoice_timing_from_bolt11(&invoice).map_err(js_err)?;

    if reverse_response.onchain_amount < quote.required_lockup_sat {
        return Err(js_err(format!(
            "Boltz lockup amount {} sats is below the required {} sats for the current inscription transaction.",
            reverse_response.onchain_amount, quote.required_lockup_sat
        )));
    }

    let expected_commit_sat = reverse_response
        .onchain_amount
        .checked_sub(quote.claim_fee_sat)
        .ok_or_else(|| js_err("Estimated claim fee leaves no commit output value."))?;
    let expected_receive_sat = expected_commit_sat
        .checked_sub(quote.reveal_fee_sat)
        .ok_or_else(|| js_err("Estimated reveal fee leaves no final Liquid output value."))?;
    if expected_receive_sat == 0 {
        return Err(js_err(
            "Estimated reveal fee leaves a zero-valued final Liquid output.",
        ));
    }

    let status = build_status_view(
        Some(reverse_response.id.as_str()),
        Some("swap.created"),
        None,
        None,
        None,
        Some("Invoice created. Pay it in your Lightning wallet.".to_owned()),
    );

    let display = SwapDisplayDetails {
        invoice_amount_sat: quote.invoice_amount_sat,
        invoice: invoice.clone(),
        invoice_created_at_unix: Some(invoice_timing.created_at_unix),
        invoice_expires_at_unix: invoice_timing.expires_at_unix,
        invoice_expiry_secs: Some(invoice_timing.expiry_secs),
        commit_address: wallet.commit_address_string(),
        destination_address: quote.destination_address.to_string(),
        reveal_target_prefix_hex: inscription_spec.reveal_target_prefix_hex(),
        expected_lockup_sat: reverse_response.onchain_amount,
        expected_commit_sat,
        expected_receive_sat,
        boltz_fee_sat: quote.boltz_fee_sat,
        claim_fee_sat: quote.claim_fee_sat,
        reveal_fee_sat: quote.reveal_fee_sat,
        lockup_fee_sat: quote.lockup_fee_sat,
    };

    let active_swap = ActiveReverseSwap {
        preimage,
        swap_id: reverse_response.id.clone(),
        display: display.clone(),
        upload: current_upload.clone(),
        reverse_response,
        swap_script,
        last_status: Some("swap.created".to_owned()),
        last_lockup_txid: None,
        prepared: None,
        terminal_error: None,
    };
    let view = created_swap_view(&active_swap.swap_id, &display, status);

    Ok(CreatedReverseSwap { active_swap, view })
}

pub(crate) async fn retry_pending_swap(
    config: &SwapConfig,
    wallet: &SessionWallet,
    active_swap: &ActiveReverseSwap,
    genesis_hash: elements::BlockHash,
) -> Result<RetrySwapOutcome, JsValue> {
    let inscription_spec = active_swap.upload.to_inscription_spec().map_err(js_err)?;

    if active_swap
        .last_status
        .as_deref()
        .is_some_and(is_terminal_status)
    {
        return Err(js_err(
            "Boltz already marked this swap terminal. Create a new invoice instead.",
        ));
    }

    if !active_swap
        .last_status
        .as_deref()
        .is_some_and(is_retriable_processing_status)
    {
        return Err(js_err("This swap is not yet in a retryable onchain state."));
    }

    match active_swap.prepared.as_ref() {
        Some(prepared) if prepared.commit_broadcasted => {
            match commit_output_visible(config, wallet, prepared).await {
                Ok(commit_visible) if should_rebuild_reveal_on_retry(prepared, commit_visible) => {
                    Ok(RetrySwapOutcome {
                        prepared: Some(
                            rebuild_reveal_for_visible_commit(
                                config,
                                &inscription_spec,
                                wallet,
                                active_swap,
                                genesis_hash,
                                prepared,
                            )
                            .await?,
                        ),
                        message: format!(
                            "Commit {} is visible. Rebuilt reveal with current fees and will retry broadcast.",
                            prepared.commit_txid
                        ),
                    })
                }
                Ok(commit_visible) => Ok(retry_swap_outcome(
                    active_swap.prepared.clone(),
                    commit_visible,
                )),
                Err(err) => {
                    let error_message = err
                        .as_string()
                        .unwrap_or_else(|| "unknown error".to_owned());
                    if is_transient_commit_visibility_error_message(&error_message) {
                        Ok(RetrySwapOutcome {
                            prepared: active_swap.prepared.clone(),
                            message: format!(
                                "Keeping existing commit {} despite a temporary visibility-check error: {}. Polling will retry reveal {}.",
                                prepared.commit_txid, error_message, prepared.reveal.txid
                            ),
                        })
                    } else {
                        Err(err)
                    }
                }
            }
        }
        _ => Ok(retry_swap_outcome(active_swap.prepared.clone(), false)),
    }
}

pub(crate) async fn poll_active_swap(
    config: &SwapConfig,
    wallet: &SessionWallet,
    active_swap: &ActiveReverseSwap,
    genesis_hash: elements::BlockHash,
) -> Result<SwapPollOutcome, JsValue> {
    if active_swap.terminal_error.is_some()
        || active_swap
            .prepared
            .as_ref()
            .is_some_and(|prepared| prepared.reveal_broadcasted)
    {
        return Ok(SwapPollOutcome {
            status_view: build_status_view(
                Some(active_swap.swap_id.as_str()),
                active_swap.last_status.as_deref(),
                active_swap.last_lockup_txid.as_deref(),
                active_swap.prepared.as_ref(),
                active_swap.terminal_error.as_deref(),
                None,
            ),
            state_update: None,
        });
    }

    let inscription_spec = active_swap.upload.to_inscription_spec().map_err(js_err)?;
    let boltz_client = create_boltz_client(config);
    let swap_response = boltz_client
        .get_swap(&active_swap.swap_id)
        .await
        .map_err(|err| js_err(err.to_string()))?;
    let raw_status = swap_response.status.clone();
    let (lockup_tx, lockup_txid) =
        lockup_from_boltz(config, &boltz_client, &active_swap.swap_id, &swap_response).await?;
    let effective_lockup_txid = lockup_txid
        .clone()
        .or_else(|| active_swap.last_lockup_txid.clone());
    let mut state = SwapProcessState {
        prepared: active_swap.prepared.clone(),
        terminal_error: active_swap.terminal_error.clone(),
        message_override: None,
    };
    let context = SwapProcessContext {
        config,
        fee_policy: FeePolicy::liquid_default(),
        wallet,
        active_swap,
        inscription_spec: &inscription_spec,
        boltz_client: &boltz_client,
        genesis_hash,
        raw_status: &raw_status,
        lockup_tx,
        effective_lockup_txid: effective_lockup_txid.clone(),
    };

    run_processing_pipeline(&context, &mut state).await?;

    Ok(SwapPollOutcome {
        status_view: build_status_view(
            Some(active_swap.swap_id.as_str()),
            Some(raw_status.as_str()),
            effective_lockup_txid.as_deref(),
            state.prepared.as_ref(),
            state.terminal_error.as_deref(),
            state.message_override,
        ),
        state_update: Some(SwapStateUpdate {
            raw_status,
            effective_lockup_txid,
            prepared: state.prepared,
            terminal_error: state.terminal_error,
        }),
    })
}

async fn run_processing_pipeline(
    context: &SwapProcessContext<'_>,
    state: &mut SwapProcessState,
) -> Result<(), JsValue> {
    for _ in 0..3 {
        let step = derive_processing_step(
            context.raw_status,
            state.prepared.as_ref(),
            state.terminal_error.as_deref(),
            context.effective_lockup_txid.as_deref(),
            context.lockup_tx.is_some(),
        );
        let advanced = execute_processing_step(context, state, step).await?;
        if !advanced || state.terminal_error.is_some() {
            break;
        }
    }

    Ok(())
}

async fn execute_processing_step(
    context: &SwapProcessContext<'_>,
    state: &mut SwapProcessState,
    step: SwapProcessingStep,
) -> Result<bool, JsValue> {
    match step {
        SwapProcessingStep::NoOp => Ok(false),
        SwapProcessingStep::WaitForLockup => {
            state.message_override = Some(lockup_wait_message(
                context.raw_status,
                context.effective_lockup_txid.as_deref(),
            ));
            Ok(false)
        }
        SwapProcessingStep::PrepareTransactions => {
            let prepare_context = PrepareTransactionsContext {
                config: context.config,
                fee_policy: context.fee_policy,
                inscription_spec: context.inscription_spec,
                wallet: context.wallet,
                active_swap: context.active_swap,
                boltz_client: context.boltz_client,
                genesis_hash: context.genesis_hash,
                lockup_tx: context.lockup_tx.clone(),
            };
            match prepare_transactions(&prepare_context).await {
                Ok(new_prepared) => {
                    state.message_override = Some(ready_to_broadcast_commit_message());
                    state.prepared = Some(new_prepared);
                    Ok(true)
                }
                Err(err) => {
                    let message = err
                        .as_string()
                        .unwrap_or_else(|| "unknown error".to_owned());
                    if is_lockup_wait_error(&message) {
                        state.message_override = Some(lockup_wait_message(
                            context.raw_status,
                            context.effective_lockup_txid.as_deref(),
                        ));
                    } else {
                        state.terminal_error = Some(format!(
                            "Failed to prepare commit/reveal transactions: {}",
                            message
                        ));
                    }
                    Ok(false)
                }
            }
        }
        SwapProcessingStep::BroadcastCommit => {
            let Some(prepared) = state.prepared.as_mut() else {
                return Ok(false);
            };
            broadcast_prepared_commit(
                context,
                prepared,
                &mut state.message_override,
                &mut state.terminal_error,
            )
            .await
        }
        SwapProcessingStep::BroadcastReveal => {
            let Some(prepared) = state.prepared.as_mut() else {
                return Ok(false);
            };
            broadcast_prepared_reveal(
                context.config,
                context.wallet,
                prepared,
                &mut state.message_override,
                &mut state.terminal_error,
            )
            .await
        }
    }
}

async fn broadcast_prepared_commit(
    context: &SwapProcessContext<'_>,
    prepared: &mut PreparedSwapTransactions,
    message_override: &mut Option<String>,
    terminal_error: &mut Option<String>,
) -> Result<bool, JsValue> {
    match context.effective_lockup_txid.as_deref() {
        Some(lockup_txid) => {
            match lockup_output_visible(context.config, context.active_swap, lockup_txid).await {
                Ok(true) => {
                    if let Err(err) =
                        broadcast_liquid_transaction(context.config, &prepared.commit_tx).await
                    {
                        let error_message = err
                            .as_string()
                            .unwrap_or_else(|| "unknown error".to_owned());
                        if is_missing_or_spent_input_error_message(&error_message) {
                            *message_override = Some(waiting_for_commit_broadcast_message());
                        } else if is_rate_limited_error_message(&error_message) {
                            *message_override = Some(retrying_commit_broadcast_message());
                        } else {
                            *terminal_error = Some(format!(
                                "Commit broadcast failed for {}: {}",
                                prepared.commit_txid, error_message
                            ));
                        }
                        Ok(false)
                    } else {
                        prepared.commit_broadcasted = true;
                        *message_override = Some(waiting_for_reveal_broadcast_message());
                        Ok(true)
                    }
                }
                Ok(false) => {
                    *message_override = Some(waiting_for_commit_broadcast_message());
                    Ok(false)
                }
                Err(err) => {
                    let error_message = err
                        .as_string()
                        .unwrap_or_else(|| "unknown error".to_owned());
                    if is_transient_commit_visibility_error_message(&error_message) {
                        *message_override = Some(retrying_commit_broadcast_message());
                    } else {
                        *terminal_error = Some(format!(
                            "Boltz lockup tx {} is known, but lockup visibility check failed before commit {}: {}",
                            lockup_txid, prepared.commit_txid, error_message
                        ));
                    }
                    Ok(false)
                }
            }
        }
        None => {
            *message_override = Some(lockup_wait_message(
                context.raw_status,
                context.effective_lockup_txid.as_deref(),
            ));
            Ok(false)
        }
    }
}

async fn broadcast_prepared_reveal(
    config: &SwapConfig,
    wallet: &SessionWallet,
    prepared: &mut PreparedSwapTransactions,
    message_override: &mut Option<String>,
    terminal_error: &mut Option<String>,
) -> Result<bool, JsValue> {
    match commit_output_visible(config, wallet, prepared).await {
        Ok(true) => {
            if let Err(err) = broadcast_liquid_transaction(config, &prepared.reveal.tx).await {
                let error_message = err
                    .as_string()
                    .unwrap_or_else(|| "unknown error".to_owned());
                if is_missing_or_spent_input_error_message(&error_message) {
                    *message_override = Some(waiting_for_reveal_broadcast_message());
                } else if is_rate_limited_error_message(&error_message) {
                    *message_override = Some(retrying_reveal_broadcast_message());
                } else {
                    *terminal_error = Some(format!(
                        "Commit tx {} broadcast, but reveal broadcast failed: {}",
                        prepared.commit_txid, error_message
                    ));
                }
                Ok(false)
            } else {
                prepared.reveal_broadcasted = true;
                *message_override = Some(reveal_broadcast_message());
                Ok(true)
            }
        }
        Ok(false) => {
            *message_override = Some(waiting_for_reveal_broadcast_message());
            Ok(false)
        }
        Err(err) => {
            let error_message = err
                .as_string()
                .unwrap_or_else(|| "unknown error".to_owned());
            if is_transient_commit_visibility_error_message(&error_message) {
                *message_override = Some(retrying_reveal_broadcast_message());
            } else {
                *terminal_error = Some(format!(
                    "Commit tx {} broadcast, but commit visibility check failed: {}",
                    prepared.commit_txid, error_message
                ));
            }
            Ok(false)
        }
    }
}

pub(crate) fn derive_processing_step(
    status: &str,
    prepared: Option<&PreparedSwapTransactions>,
    terminal_error: Option<&str>,
    lockup_txid: Option<&str>,
    has_lockup_tx: bool,
) -> SwapProcessingStep {
    if !should_process_swap(status, prepared, terminal_error) {
        return SwapProcessingStep::NoOp;
    }

    if prepared.is_none() {
        if !lockup_ready_for_preparation(lockup_txid, has_lockup_tx) {
            return SwapProcessingStep::WaitForLockup;
        }
        return SwapProcessingStep::PrepareTransactions;
    }

    let prepared = prepared.expect("checked above");
    if !prepared.commit_broadcasted {
        return SwapProcessingStep::BroadcastCommit;
    }
    if !prepared.reveal_broadcasted {
        return SwapProcessingStep::BroadcastReveal;
    }

    SwapProcessingStep::NoOp
}

fn create_boltz_client(config: &SwapConfig) -> BoltzApiClientV2 {
    BoltzApiClientV2::new(config.boltz_api_url.to_owned(), None)
}

fn create_liquid_esplora_client(config: &SwapConfig) -> EsploraLiquidClient {
    EsploraLiquidClient::new(
        config.liquid_chain,
        config.liquid_esplora_url,
        LIQUID_CLIENT_TIMEOUT_SECS,
    )
}

fn create_liquid_chain_client(config: &SwapConfig) -> ChainClient {
    ChainClient::new().with_liquid(create_liquid_esplora_client(config))
}

async fn reverse_pair(client: &BoltzApiClientV2) -> Result<ReversePair, JsValue> {
    client
        .get_reverse_pairs()
        .await
        .map_err(|err| js_err(err.to_string()))?
        .get_btc_to_lbtc_pair()
        .ok_or_else(|| js_err("Boltz does not currently expose a BTC -> L-BTC reverse pair."))
}

pub(crate) fn minimum_reverse_invoice_amount(
    pair: &ReversePair,
    claim_fee_sat: u64,
    reveal_fee_sat: u64,
    minimum_final_output_sat: u64,
) -> Result<ReverseSwapSizing, String> {
    let required_lockup_sat = claim_fee_sat
        .checked_add(reveal_fee_sat)
        .and_then(|amount| amount.checked_add(minimum_final_output_sat))
        .ok_or_else(|| "Required lockup amount overflowed.".to_owned())?;

    let mut low = pair.limits.minimal.max(required_lockup_sat);
    let mut high = pair.limits.maximal;
    let mut best = None;

    while low <= high {
        let mid = low + ((high - low) / 2);
        let boltz_fee_sat = pair.fees.boltz(mid);
        let lockup_fee_sat = pair.fees.lockup();
        let lockup_sat = mid
            .checked_sub(boltz_fee_sat + lockup_fee_sat)
            .ok_or_else(|| "Reverse invoice sizing underflowed.".to_owned())?;

        if lockup_sat >= required_lockup_sat {
            best = Some(mid);
            if mid == 0 {
                break;
            }
            high = mid - 1;
        } else {
            low = mid
                .checked_add(1)
                .ok_or_else(|| "Reverse invoice sizing overflowed.".to_owned())?;
        }
    }

    let invoice_amount_sat = best.ok_or_else(|| {
        format!(
            "Boltz reverse pair cannot fund the required {} sat lockup within its current limits.",
            required_lockup_sat
        )
    })?;

    Ok(ReverseSwapSizing {
        invoice_amount_sat,
        required_lockup_sat,
    })
}

pub(crate) fn destination_address_from_active_swap(
    active_swap: &ActiveReverseSwap,
) -> Result<elements::Address, String> {
    parse_confidential_destination_address(&active_swap.display.destination_address)
}

fn lockup_address_from_active_swap(
    active_swap: &ActiveReverseSwap,
) -> Result<elements::Address, String> {
    elements::Address::from_str(&active_swap.reverse_response.lockup_address)
        .map_err(|err| format!("Invalid Boltz lockup address: {err}"))
}

pub(crate) fn relay_adjusted_commit_fee_sat(config: &SwapConfig, fee_policy: FeePolicy) -> u64 {
    estimate_claim_fee(config.chain, fee_policy.effective_sat_per_vb())
        .to_sat()
        .checked_add(fee_policy.safety_buffer_sat)
        .expect("commit fee safety buffer overflowed")
}

fn liquid_fee_sats_from_vsize(vbytes: u64, fee_policy: FeePolicy) -> Result<u64, String> {
    let effective_fee_rate_sat_per_vb = fee_policy.effective_sat_per_vb();
    if !effective_fee_rate_sat_per_vb.is_finite() || effective_fee_rate_sat_per_vb <= 0.0 {
        return Err(format!(
            "Liquid fee rate must be positive and finite, got {effective_fee_rate_sat_per_vb}"
        ));
    }

    let fee_sat = (vbytes as f64 * effective_fee_rate_sat_per_vb).ceil();
    if !fee_sat.is_finite() || fee_sat > u64::MAX as f64 {
        return Err("Liquid fee calculation overflowed.".to_owned());
    }

    (fee_sat as u64)
        .checked_add(fee_policy.safety_buffer_sat)
        .ok_or_else(|| "Liquid fee calculation overflowed.".to_owned())
}

fn liquid_discounted_vsize(tx: &elements::Transaction) -> u64 {
    tx.discount_vsize() as u64
}

async fn construct_commit_tx_with_fee(
    context: &CommitBuildContext<'_>,
    fee_sat: u64,
) -> Result<elements::Transaction, JsValue> {
    let options = context
        .lockup_tx
        .clone()
        .map(|lockup_tx| TransactionOptions::default().with_lockup_tx(lockup_tx));
    let commit_tx = context
        .active_swap
        .swap_script
        .construct_claim(
            &context.active_swap.preimage,
            SwapTransactionParams {
                keys: context.wallet.claim_keys,
                output_address: context.wallet.commit_address_string(),
                fee: Fee::Absolute(fee_sat),
                swap_id: context.active_swap.swap_id.clone(),
                chain_client: context.chain_client,
                boltz_client: context.boltz_client,
                options,
            },
        )
        .await
        .map_err(|err| js_err(err.to_string()))?;

    commit_tx
        .as_liquid()
        .cloned()
        .ok_or_else(|| js_err("Expected a Liquid claim transaction."))
}

async fn construct_exact_commit_tx(
    config: &SwapConfig,
    fee_policy: FeePolicy,
    context: &CommitBuildContext<'_>,
) -> Result<elements::Transaction, JsValue> {
    let mut fee_sat = relay_adjusted_commit_fee_sat(config, fee_policy);

    for _ in 0..fee_policy.max_convergence_passes {
        let commit_tx = construct_commit_tx_with_fee(context, fee_sat).await?;
        let exact_fee_sat =
            liquid_fee_sats_from_vsize(liquid_discounted_vsize(&commit_tx), fee_policy)
                .map_err(js_err)?;
        if exact_fee_sat == fee_sat {
            return Ok(commit_tx);
        }
        fee_sat = exact_fee_sat;
    }

    let commit_tx = construct_commit_tx_with_fee(context, fee_sat).await?;
    let exact_fee_sat = liquid_fee_sats_from_vsize(liquid_discounted_vsize(&commit_tx), fee_policy)
        .map_err(js_err)?;
    if exact_fee_sat == fee_sat {
        Ok(commit_tx)
    } else {
        Err(js_err(format!(
            "Commit fee did not converge after {} passes: built with {} sats, but final size requires {} sats.",
            fee_policy.max_convergence_passes, fee_sat, exact_fee_sat
        )))
    }
}

async fn prepare_transactions(
    context: &PrepareTransactionsContext<'_>,
) -> Result<PreparedSwapTransactions, JsValue> {
    let destination_address =
        destination_address_from_active_swap(context.active_swap).map_err(js_err)?;
    let chain_client = create_liquid_chain_client(context.config);
    let build_context = CommitBuildContext {
        wallet: context.wallet,
        active_swap: context.active_swap,
        boltz_client: context.boltz_client,
        chain_client: &chain_client,
        lockup_tx: context.lockup_tx.clone(),
    };
    let commit_tx =
        construct_exact_commit_tx(context.config, context.fee_policy, &build_context).await?;
    let commit_output = commit_tx
        .output
        .first()
        .cloned()
        .ok_or_else(|| js_err("Commit transaction is missing its commit output."))?;
    let reveal = context
        .wallet
        .inscription_wallet()
        .prepare_reveal(
            RevealContext {
                chain: context.config.liquid_chain,
                spec: context.inscription_spec,
                destination: &destination_address,
                genesis_hash: context.genesis_hash,
                commit_txid: commit_tx.txid(),
                commit_output: &commit_output,
            },
            RevealFeePolicy::new(
                context.fee_policy.target_sat_per_vb,
                context.fee_policy.relay_min_sat_per_vb,
            ),
        )
        .map_err(js_err)?;

    Ok(PreparedSwapTransactions {
        commit_txid: commit_tx.txid().to_string(),
        commit_tx,
        reveal,
        commit_broadcasted: false,
        reveal_broadcasted: false,
    })
}

async fn rebuild_reveal_for_visible_commit(
    config: &SwapConfig,
    inscription_spec: &InscriptionSpec,
    wallet: &SessionWallet,
    active_swap: &ActiveReverseSwap,
    genesis_hash: elements::BlockHash,
    prepared: &PreparedSwapTransactions,
) -> Result<PreparedSwapTransactions, JsValue> {
    let destination_address = destination_address_from_active_swap(active_swap).map_err(js_err)?;
    let fee_policy = FeePolicy::liquid_default();
    let commit_output = prepared
        .commit_tx
        .output
        .first()
        .cloned()
        .ok_or_else(|| js_err("Stored commit transaction is missing its commit output."))?;
    let reveal = wallet
        .inscription_wallet()
        .prepare_reveal(
            RevealContext {
                chain: config.liquid_chain,
                spec: inscription_spec,
                destination: &destination_address,
                genesis_hash,
                commit_txid: prepared.commit_tx.txid(),
                commit_output: &commit_output,
            },
            RevealFeePolicy::new(
                fee_policy.target_sat_per_vb,
                fee_policy.relay_min_sat_per_vb,
            ),
        )
        .map_err(js_err)?;

    Ok(PreparedSwapTransactions {
        commit_tx: prepared.commit_tx.clone(),
        commit_txid: prepared.commit_txid.clone(),
        reveal,
        commit_broadcasted: true,
        reveal_broadcasted: false,
    })
}

#[cfg(target_arch = "wasm32")]
async fn broadcast_liquid_transaction(
    config: &SwapConfig,
    tx: &elements::Transaction,
) -> Result<(), JsValue> {
    let tx_hex = liquid_tx_to_hex(tx);
    let window = web_sys::window().ok_or_else(|| js_err("Browser window is not available."))?;
    let init = web_sys::RequestInit::new();
    init.set_method("POST");
    init.set_body(&JsValue::from_str(&tx_hex));

    let request = web_sys::Request::new_with_str_and_init(
        &format!("{}/tx", config.liquid_esplora_url),
        &init,
    )
    .map_err(|err| {
        js_err(format!(
            "Failed to build Liquid broadcast request: {:?}",
            err
        ))
    })?;
    request
        .headers()
        .set("Content-Type", "text/plain;charset=utf-8")
        .map_err(|err| js_err(format!("Failed to set Liquid broadcast headers: {:?}", err)))?;

    let response = JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(|err| js_err(format!("Liquid broadcast request failed: {:?}", err)))?;
    let response: web_sys::Response = response
        .dyn_into()
        .map_err(|_| js_err("Liquid broadcast response had an unexpected type."))?;
    let status = response.status();
    let status_text = response.status_text();
    let body = JsFuture::from(response.text().map_err(|err| {
        js_err(format!(
            "Failed to read Liquid broadcast response: {:?}",
            err
        ))
    })?)
    .await
    .map_err(|err| {
        js_err(format!(
            "Failed to decode Liquid broadcast response: {:?}",
            err
        ))
    })?
    .as_string()
    .unwrap_or_default();

    if response.ok() {
        Ok(())
    } else {
        let trimmed_body = body.trim();
        let detail = if trimmed_body.is_empty() {
            status_text
        } else {
            trimmed_body.to_owned()
        };
        Err(js_err(format!(
            "Liquid broadcast HTTP {}: {}",
            status, detail
        )))
    }
}

#[cfg(not(target_arch = "wasm32"))]
async fn broadcast_liquid_transaction(
    config: &SwapConfig,
    tx: &elements::Transaction,
) -> Result<(), JsValue> {
    create_liquid_chain_client(config)
        .try_broadcast_tx(&BtcLikeTransaction::liquid(tx.clone()))
        .await
        .map_err(|err| js_err(err.to_string()))
}

async fn commit_output_visible(
    config: &SwapConfig,
    wallet: &SessionWallet,
    prepared: &PreparedSwapTransactions,
) -> Result<bool, JsValue> {
    let client = create_liquid_esplora_client(config);
    let commit_address = wallet.commit_address().to_unconfidential();
    let utxo = match client.get_address_utxo(&commit_address).await {
        Ok(utxo) => utxo,
        Err(err) if is_missing_liquid_utxo_error(&err) => return Ok(false),
        Err(err) => return Err(js_err(err.to_string())),
    };

    Ok(utxo.is_some_and(|(outpoint, _)| {
        outpoint.txid.to_string() == prepared.commit_txid && outpoint.vout == 0
    }))
}

async fn lockup_output_visible(
    config: &SwapConfig,
    active_swap: &ActiveReverseSwap,
    expected_lockup_txid: &str,
) -> Result<bool, JsValue> {
    let client = create_liquid_esplora_client(config);
    let lockup_address = lockup_address_from_active_swap(active_swap).map_err(js_err)?;
    let utxo = match client.get_address_utxo(&lockup_address).await {
        Ok(utxo) => utxo,
        Err(err) if is_missing_liquid_utxo_error(&err) => return Ok(false),
        Err(err) => return Err(js_err(err.to_string())),
    };

    Ok(utxo.is_some_and(|(outpoint, _)| outpoint.txid.to_string() == expected_lockup_txid))
}

pub(crate) fn is_missing_liquid_utxo_error(err: &BoltzClientError) -> bool {
    matches!(
        err,
        BoltzClientError::Protocol(message)
            if message == "Esplora could not find a Liquid UTXO for script"
    )
}

pub(crate) fn is_transient_commit_visibility_error_message(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("failed to fill whole buffer")
        || lower.contains("unexpected eof")
        || lower.contains("timed out")
        || lower.contains("timeout")
        || lower.contains("connection reset")
        || lower.contains("connection closed")
        || lower.contains("temporarily unavailable")
        || lower.contains("service unavailable")
        || lower.contains("too many requests")
        || lower.contains(" 429 ")
        || lower.contains("http error: 429")
}

pub(crate) fn is_missing_or_spent_input_error_message(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("bad-txns-inputs-missingorspent")
        || lower.contains("missingorspent")
        || lower.contains("inputs-missingorspent")
}

pub(crate) fn is_rate_limited_error_message(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("too many requests")
        || lower.contains("http error: 429")
        || lower.contains("status code 429")
}

pub(crate) fn lockup_tx_from_response(
    chain: boltz_client::network::Chain,
    swap_response: &boltz_client::boltz::GetSwapResponse,
) -> Result<Option<BtcLikeTransaction>, JsValue> {
    swap_response
        .transaction
        .as_ref()
        .map(|tx| {
            BtcLikeTransaction::from_hex(chain, &tx.hex).map_err(|err| js_err(err.to_string()))
        })
        .transpose()
}

pub(crate) fn reverse_lockup_tx_from_response(
    chain: boltz_client::network::Chain,
    response: &boltz_client::boltz::ReverseSwapTxResp,
) -> Result<Option<BtcLikeTransaction>, JsValue> {
    response
        .hex
        .as_ref()
        .map(|hex| BtcLikeTransaction::from_hex(chain, hex).map_err(|err| js_err(err.to_string())))
        .transpose()
}

fn btc_like_txid(chain: boltz_client::network::Chain, tx: &BtcLikeTransaction) -> String {
    match chain {
        boltz_client::network::Chain::Bitcoin(_) => tx
            .as_bitcoin()
            .expect("bitcoin tx expected for bitcoin chain")
            .compute_txid()
            .to_string(),
        boltz_client::network::Chain::Liquid(_) => tx
            .as_liquid()
            .expect("liquid tx expected for liquid chain")
            .txid()
            .to_string(),
    }
}

pub(crate) fn lockup_txid_from_response(
    chain: boltz_client::network::Chain,
    swap_response: &boltz_client::boltz::GetSwapResponse,
    parsed_lockup_tx: Option<&BtcLikeTransaction>,
) -> Result<Option<String>, JsValue> {
    let provided = swap_response.transaction.as_ref().and_then(|tx| {
        let trimmed = tx.id.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_owned())
        }
    });

    if provided.is_some() {
        return Ok(provided);
    }

    let derived = match (chain, parsed_lockup_tx) {
        (boltz_client::network::Chain::Bitcoin(_), Some(lockup_tx)) => lockup_tx
            .as_bitcoin()
            .map(|tx| tx.compute_txid().to_string()),
        (boltz_client::network::Chain::Liquid(_), Some(lockup_tx)) => {
            lockup_tx.as_liquid().map(|tx| tx.txid().to_string())
        }
        (_, None) => None,
    };

    Ok(derived)
}

pub(crate) fn lockup_txid_from_reverse_response(
    chain: boltz_client::network::Chain,
    response: &boltz_client::boltz::ReverseSwapTxResp,
    parsed_lockup_tx: Option<&BtcLikeTransaction>,
) -> Option<String> {
    let provided = {
        let trimmed = response.id.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_owned())
        }
    };

    provided.or_else(|| parsed_lockup_tx.map(|tx| btc_like_txid(chain, tx)))
}

async fn lockup_from_boltz(
    config: &SwapConfig,
    boltz_client: &BoltzApiClientV2,
    swap_id: &str,
    swap_response: &boltz_client::boltz::GetSwapResponse,
) -> Result<(Option<BtcLikeTransaction>, Option<String>), JsValue> {
    let mut lockup_tx = lockup_tx_from_response(config.chain, swap_response)?;
    let mut lockup_txid =
        lockup_txid_from_response(config.chain, swap_response, lockup_tx.as_ref())?;

    if lockup_ready_for_preparation(lockup_txid.as_deref(), lockup_tx.is_some()) {
        return Ok((lockup_tx, lockup_txid));
    }

    if let Ok(reverse_tx) = boltz_client.get_reverse_tx(swap_id).await {
        let reverse_lockup_tx = reverse_lockup_tx_from_response(config.chain, &reverse_tx)?;
        let reverse_lockup_txid = lockup_txid_from_reverse_response(
            config.chain,
            &reverse_tx,
            reverse_lockup_tx.as_ref(),
        );
        if lockup_tx.is_none() {
            lockup_tx = reverse_lockup_tx;
        }
        if lockup_txid.is_none() {
            lockup_txid = reverse_lockup_txid;
        }
    }

    Ok((lockup_tx, lockup_txid))
}

pub(crate) fn is_lockup_wait_error(message: &str) -> bool {
    message.contains("Esplora could not find a Liquid UTXO for script")
        || message.contains("No transaction hex found in boltz response")
}

pub(crate) fn lockup_ready_for_preparation(lockup_txid: Option<&str>, has_lockup_tx: bool) -> bool {
    lockup_txid.is_some() && has_lockup_tx
}

pub(crate) fn lockup_wait_message(raw_status: &str, lockup_txid: Option<&str>) -> String {
    match (raw_status, lockup_txid) {
        ("invoice.settled", Some(_)) => {
            "Lightning invoice paid. Waiting for Boltz lockup transaction details.".to_owned()
        }
        ("invoice.settled", None) => {
            "Lightning invoice paid. Waiting for Boltz lockup transaction.".to_owned()
        }
        (_, Some(_)) => "Swap funded. Waiting for Boltz lockup transaction details.".to_owned(),
        _ => "Swap funded. Waiting for Boltz lockup transaction.".to_owned(),
    }
}

fn waiting_to_prepare_transactions_message() -> String {
    "Waiting to prepare commit and reveal transactions.".to_owned()
}

fn ready_to_broadcast_commit_message() -> String {
    "Commit and reveal transactions are ready. Waiting to broadcast commit.".to_owned()
}

fn waiting_for_commit_broadcast_message() -> String {
    "Waiting for Boltz lockup output before broadcasting commit.".to_owned()
}

fn retrying_commit_broadcast_message() -> String {
    "Waiting to retry commit broadcast.".to_owned()
}

fn waiting_for_reveal_broadcast_message() -> String {
    "Waiting for commit output before broadcasting reveal.".to_owned()
}

fn retrying_reveal_broadcast_message() -> String {
    "Waiting to retry reveal broadcast.".to_owned()
}

fn reveal_broadcast_message() -> String {
    "Reveal transaction broadcast. Waiting for confirmation.".to_owned()
}

pub(crate) fn should_process_swap(
    status: &str,
    prepared: Option<&PreparedSwapTransactions>,
    terminal_error: Option<&str>,
) -> bool {
    terminal_error.is_none()
        && is_retriable_processing_status(status)
        && !prepared.is_some_and(|prepared| prepared.reveal_broadcasted)
}

pub(crate) fn is_retriable_processing_status(status: &str) -> bool {
    matches!(
        status,
        "transaction.mempool" | "transaction.confirmed" | "invoice.settled"
    )
}

pub(crate) fn should_rebuild_reveal_on_retry(
    prepared: &PreparedSwapTransactions,
    commit_visible: bool,
) -> bool {
    prepared.commit_broadcasted && commit_visible
}

pub(crate) fn retry_swap_outcome(
    prepared: Option<PreparedSwapTransactions>,
    commit_visible: bool,
) -> RetrySwapOutcome {
    match prepared {
        Some(prepared) if prepared.commit_broadcasted && commit_visible => RetrySwapOutcome {
            message: format!(
                "Keeping existing commit {} because its output is visible. Resuming reveal {}.",
                prepared.commit_txid, prepared.reveal.txid
            ),
            prepared: Some(prepared),
        },
        Some(prepared) if prepared.commit_broadcasted => RetrySwapOutcome {
            message: format!(
                "Discarded prepared commit/reveal because commit {} is not visible. Polling will rebuild with current fees.",
                prepared.commit_txid
            ),
            prepared: None,
        },
        Some(_) => RetrySwapOutcome {
            message:
                "Discarded unbroadcast prepared commit/reveal. Polling will rebuild with current fees."
                    .to_owned(),
            prepared: None,
        },
        None => RetrySwapOutcome {
            message: "No prepared transactions were stored. Polling will build them with current fees."
                .to_owned(),
            prepared: None,
        },
    }
}

pub(crate) fn active_swap_is_finished(active: &ActiveReverseSwap) -> bool {
    active.terminal_error.is_some()
        || active
            .prepared
            .as_ref()
            .is_some_and(|prepared| prepared.reveal_broadcasted)
        || active
            .last_status
            .as_deref()
            .is_some_and(is_terminal_status)
}

pub(crate) fn is_terminal_status(status: &str) -> bool {
    matches!(
        status,
        "invoice.expired" | "swap.expired" | "transaction.failed"
    )
}

pub(crate) fn build_status_view(
    swap_id: Option<&str>,
    raw_status: Option<&str>,
    lockup_txid: Option<&str>,
    prepared: Option<&PreparedSwapTransactions>,
    terminal_error: Option<&str>,
    message_override: Option<String>,
) -> UiSwapStatusView {
    let commit_txid = prepared.map(|prepared| prepared.commit_txid.clone());
    let commit_tx_hex = prepared.map(|prepared| liquid_tx_to_hex(&prepared.commit_tx));
    let reveal_txid = prepared.map(|prepared| prepared.reveal.txid.clone());
    let reveal_tx_hex = prepared.map(|prepared| liquid_tx_to_hex(&prepared.reveal.tx));

    let phase = if terminal_error.is_some() {
        "client_failed"
    } else if prepared.is_some_and(|prepared| prepared.reveal_broadcasted) {
        "complete"
    } else {
        match raw_status {
            None => "idle",
            Some("swap.created") => "invoice_ready",
            Some("transaction.mempool" | "transaction.confirmed" | "invoice.settled")
                if prepared.is_some_and(|prepared| prepared.commit_broadcasted) =>
            {
                "commit_broadcast"
            }
            Some("transaction.mempool" | "transaction.confirmed" | "invoice.settled")
                if prepared.is_some() =>
            {
                "commit_built"
            }
            Some("transaction.mempool" | "transaction.confirmed") => "building_transactions",
            Some("invoice.settled") => "invoice_paid",
            Some("invoice.expired") => "invoice_expired",
            Some("swap.expired") => "swap_expired",
            Some("transaction.failed") => "transaction_failed",
            _ => "waiting",
        }
    };

    let is_terminal = terminal_error.is_some()
        || prepared.is_some_and(|prepared| prepared.reveal_broadcasted)
        || raw_status.is_some_and(is_terminal_status);
    let default_message = if let Some(error) = terminal_error {
        error.to_owned()
    } else if let Some(prepared) = prepared {
        if prepared.reveal_broadcasted {
            reveal_broadcast_message()
        } else if prepared.commit_broadcasted {
            waiting_for_reveal_broadcast_message()
        } else if matches!(
            raw_status,
            Some("transaction.mempool" | "transaction.confirmed" | "invoice.settled")
        ) {
            ready_to_broadcast_commit_message()
        } else {
            status_default_message(raw_status, lockup_txid)
        }
    } else {
        status_default_message(raw_status, lockup_txid)
    };

    UiSwapStatusView {
        phase: phase.to_owned(),
        raw_status: raw_status.map(str::to_owned),
        message: message_override.unwrap_or(default_message),
        is_terminal,
        swap_id: swap_id.map(str::to_owned),
        commit_broadcasted: prepared.is_some_and(|prepared| prepared.commit_broadcasted),
        commit_txid,
        commit_tx_hex,
        reveal_broadcasted: prepared.is_some_and(|prepared| prepared.reveal_broadcasted),
        reveal_txid,
        reveal_tx_hex,
        lockup_txid: lockup_txid.map(str::to_owned),
    }
}

fn status_default_message(raw_status: Option<&str>, lockup_txid: Option<&str>) -> String {
    match (raw_status, lockup_txid) {
        (None, _) => "No active swap. Create an invoice to start.".to_owned(),
        (Some("swap.created"), _) => "Invoice created. Waiting for payment.".to_owned(),
        (Some("transaction.mempool"), Some(_)) => waiting_to_prepare_transactions_message(),
        (Some("transaction.confirmed"), Some(_)) => waiting_to_prepare_transactions_message(),
        (Some("invoice.settled"), Some(_)) => waiting_to_prepare_transactions_message(),
        (Some("invoice.settled"), _) => {
            "Lightning invoice paid. Waiting for Boltz lockup transaction.".to_owned()
        }
        (Some("invoice.expired"), _) => "Invoice expired before the swap completed.".to_owned(),
        (Some("swap.expired"), _) => "Swap expired before completion.".to_owned(),
        (Some("transaction.failed"), _) => {
            "Boltz marked the swap transaction as failed.".to_owned()
        }
        (Some(other), _) => format!("Current swap status: {other}"),
    }
}
