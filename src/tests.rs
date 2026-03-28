use super::*;

use crate::liquid_inscription::{InscriptionSpec, PreparedReveal};
use boltz_client::{
    ToHex,
    bitcoin::{PublicKey, hashes::Hash, key::rand::thread_rng, secp256k1::Keypair},
    boltz::{CreateReverseResponse, Leaf, ReversePair, SwapTree, SwapType},
    elements::{
        AddressParams, LockTime,
        opcodes::all::{
            OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CLTV, OP_EQUALVERIFY, OP_HASH160, OP_SIZE,
        },
        script::Builder,
        secp256k1_zkp::{Keypair as ZKKeyPair, Secp256k1 as ZKSecp256k1},
    },
    network::{Chain, LiquidChain},
    swaps::{SwapScript, fees::estimate_claim_fee},
    util::secrets::Preimage,
};

const CUSTOM_DESTINATION_ADDRESS: &str =
    "VJLGxsik4aRC4VjKt26BD5uj9t4UoaxMEXssnKNZ6o9DB9StfpzVGCKNUZCEBiGorzNdFZv1CbVEH1M6";

fn test_wallet() -> (InscriptionSpec, SessionWallet) {
    let config = SwapConfig::mainnet();
    let spec = InscriptionSpec::mainnet().expect("spec should build");
    let wallet = SessionWallet::generate(&config, &spec).expect("wallet generation should work");
    (spec, wallet)
}

fn dummy_liquid_tx(lock_time: u32) -> boltz_client::elements::Transaction {
    boltz_client::elements::Transaction {
        version: 2,
        lock_time: LockTime::from_consensus(lock_time),
        input: vec![boltz_client::elements::TxIn {
            previous_output: boltz_client::elements::OutPoint::default(),
            sequence: boltz_client::elements::Sequence::MAX,
            ..Default::default()
        }],
        output: vec![boltz_client::elements::TxOut::new_fee(
            1,
            LiquidChain::Liquid.bitcoin(),
        )],
    }
}

fn prepared_fixture(
    commit_broadcasted: bool,
    reveal_broadcasted: bool,
) -> PreparedSwapTransactions {
    let commit_tx = dummy_liquid_tx(0);
    let reveal_tx = dummy_liquid_tx(1);

    PreparedSwapTransactions {
        commit_txid: commit_tx.txid().to_string(),
        commit_tx,
        reveal: PreparedReveal {
            txid: reveal_tx.txid().to_string(),
            tx: reveal_tx,
            fee_sat: 1,
            output_amount_sat: 51,
            target_prefix_hex: "b00b".to_owned(),
            grind_nonce: 0,
        },
        commit_broadcasted,
        reveal_broadcasted,
    }
}

fn reverse_response_fixture() -> (CreateReverseResponse, Preimage, PublicKey) {
    let secp = boltz_client::bitcoin::secp256k1::Secp256k1::new();
    let mut rng = thread_rng();
    let claim_public_key = PublicKey::new(Keypair::new(&secp, &mut rng).public_key());

    let (response, preimage) = reverse_response_fixture_for_claim_public_key(claim_public_key);
    (response, preimage, claim_public_key)
}

fn reverse_response_fixture_for_claim_public_key(
    claim_public_key: PublicKey,
) -> (CreateReverseResponse, Preimage) {
    let config = SwapConfig::mainnet();
    let secp = boltz_client::bitcoin::secp256k1::Secp256k1::new();
    let zk_secp = ZKSecp256k1::new();
    let mut rng = thread_rng();

    let refund_keys = Keypair::new(&secp, &mut rng);
    let blinding_source = Keypair::new(&secp, &mut rng);
    let blinding_key =
        ZKKeyPair::from_seckey_str(&zk_secp, &blinding_source.display_secret().to_string())
            .expect("blinding key should build");
    let preimage = Preimage::random();
    let refund_public_key = PublicKey::new(refund_keys.public_key());
    let locktime = LockTime::from_consensus(500_000);

    let claim_script = Builder::new()
        .push_opcode(OP_SIZE)
        .push_int(32)
        .push_opcode(OP_EQUALVERIFY)
        .push_opcode(OP_HASH160)
        .push_slice(preimage.hash160.as_byte_array())
        .push_opcode(OP_EQUALVERIFY)
        .push_slice(&claim_public_key.inner.x_only_public_key().0.serialize())
        .push_opcode(OP_CHECKSIG)
        .into_script();

    let refund_script = Builder::new()
        .push_slice(&refund_public_key.inner.x_only_public_key().0.serialize())
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_int(locktime.to_consensus_u32().into())
        .push_opcode(OP_CLTV)
        .into_script();

    let expected_script = boltz_client::LBtcSwapScript {
        swap_type: SwapType::ReverseSubmarine,
        side: None,
        funding_addrs: None,
        hashlock: preimage.hash160,
        receiver_pubkey: claim_public_key,
        locktime,
        sender_pubkey: refund_public_key,
        blinding_key,
    };
    let lockup_address = expected_script
        .to_address(config.liquid_chain)
        .expect("expected script should have a valid address")
        .to_string();

    let response = CreateReverseResponse {
        id: "test-swap".to_owned(),
        invoice: None,
        swap_tree: SwapTree {
            claim_leaf: Leaf {
                output: claim_script.as_bytes().to_hex(),
                version: 0,
            },
            refund_leaf: Leaf {
                output: refund_script.as_bytes().to_hex(),
                version: 0,
            },
        },
        lockup_address,
        refund_public_key,
        timeout_block_height: locktime.to_consensus_u32(),
        onchain_amount: 72,
        blinding_key: Some(blinding_key.display_secret().to_string()),
    };

    (response, preimage)
}

fn swap_display_fixture(spec: &InscriptionSpec, wallet: &SessionWallet) -> SwapDisplayDetails {
    let invoice_timing =
        invoice_timing_from_bolt11(test_bolt11_invoice()).expect("fixture invoice should parse");
    SwapDisplayDetails {
        invoice_amount_sat: 84,
        invoice: test_bolt11_invoice().to_owned(),
        invoice_created_at_unix: Some(invoice_timing.created_at_unix),
        invoice_expires_at_unix: invoice_timing.expires_at_unix,
        invoice_expiry_secs: Some(invoice_timing.expiry_secs),
        commit_address: wallet.commit_address_string(),
        destination_address: spec.destination_address_string(),
        reveal_target_prefix_hex: spec.reveal_target_prefix_hex(),
        expected_lockup_sat: 72,
        expected_commit_sat: 61,
        expected_receive_sat: 52,
        boltz_fee_sat: 1,
        claim_fee_sat: 10,
        reveal_fee_sat: 9,
        lockup_fee_sat: 1,
    }
}

fn test_bolt11_invoice() -> &'static str {
    "lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpu9qrsgquk0rl77nj30yxdy8j9vdx85fkpmdla2087ne0xh8nhedh8w27kyke0lp53ut353s06fv3qfegext0eh0ymjpf39tuven09sam30g4vgpfna3rh"
}

#[test]
fn session_wallet_generation_creates_confidential_liquid_commit_address() {
    let (_, wallet) = test_wallet();

    assert!(wallet.commit_address().is_blinded());
    assert!(wallet.commit_address().is_liquid());
    assert_eq!(wallet.commit_address().params, &AddressParams::LIQUID);
}

#[test]
fn reverse_swap_fixture_validates_and_builds_liquid_script() {
    let (response, preimage, claim_public_key) = reverse_response_fixture();

    response
        .validate(
            &preimage,
            &claim_public_key,
            Chain::Liquid(LiquidChain::Liquid),
        )
        .expect("fixture response should validate");

    SwapScript::reverse_from_swap_resp(
        Chain::Liquid(LiquidChain::Liquid),
        &response,
        claim_public_key,
    )
    .expect("fixture response should build a liquid swap script");
}

#[test]
fn minimum_reverse_invoice_amount_tracks_current_claim_and_reveal_fees() {
    let pair = ReversePair {
        hash: "pair".to_owned(),
        rate: 1.0,
        limits: boltz_client::boltz::ReverseLimits {
            minimal: 1,
            maximal: 1_000_000,
        },
        fees: boltz_client::boltz::ReverseFees {
            percentage: 0.25,
            miner_fees: boltz_client::boltz::PairMinerFees {
                lockup: 27,
                claim: 0,
            },
        },
    };

    let sizing = minimum_reverse_invoice_amount(&pair, 20, 36, 1).expect("sizing should succeed");

    assert_eq!(sizing.required_lockup_sat, 57);
    assert_eq!(sizing.invoice_amount_sat, 85);
}

#[test]
fn minimum_reverse_invoice_amount_respects_pair_minimums_and_maximums() {
    let pair = ReversePair {
        hash: "pair".to_owned(),
        rate: 1.0,
        limits: boltz_client::boltz::ReverseLimits {
            minimal: 100,
            maximal: 110,
        },
        fees: boltz_client::boltz::ReverseFees {
            percentage: 0.25,
            miner_fees: boltz_client::boltz::PairMinerFees {
                lockup: 27,
                claim: 0,
            },
        },
    };

    let sizing = minimum_reverse_invoice_amount(&pair, 20, 36, 1).expect("sizing should succeed");
    assert_eq!(sizing.invoice_amount_sat, 100);

    let impossible = minimum_reverse_invoice_amount(&pair, 60, 40, 20);
    assert!(impossible.is_err());
}

#[test]
fn bolt11_invoice_timing_uses_invoice_timestamp_and_expiry() {
    let timing =
        invoice_timing_from_bolt11(test_bolt11_invoice()).expect("fixture invoice should parse");

    assert_eq!(timing.created_at_unix, 1_496_314_658);
    assert_eq!(timing.expiry_secs, 60);
    assert_eq!(timing.expires_at_unix, Some(1_496_314_718));
}

#[test]
fn commit_fee_respects_minimum_relay_rate() {
    let config = SwapConfig::mainnet();
    assert_eq!(
        relay_adjusted_commit_fee_sat(&config, FeePolicy::liquid_default()),
        estimate_claim_fee(config.chain, LIQUID_MIN_RELAY_FEE_RATE_SAT_PER_VB).to_sat()
            + LIQUID_RELAY_SAFETY_BUFFER_SAT
    );
}

#[test]
fn wallet_snapshot_roundtrip_preserves_generated_commit_address() {
    let (spec, wallet) = test_wallet();
    let restored = SessionWallet::restore(&SwapConfig::mainnet(), &spec, wallet.snapshot())
        .expect("wallet snapshot should restore");

    assert_eq!(
        restored.commit_address_string(),
        wallet.commit_address_string()
    );
    assert_eq!(restored.claim_public_key(), wallet.claim_public_key());
}

#[test]
fn upload_snapshot_roundtrip_preserves_file_metadata() {
    let upload = UploadState {
        file_name: Some("droplet.txt".to_owned()),
        content_type: "text/plain".to_owned(),
        payload: b"hello droplet".to_vec(),
        is_fallback: false,
    };

    let restored = UploadState::restore(upload.snapshot()).expect("upload should restore");

    assert_eq!(restored.file_name.as_deref(), Some("droplet.txt"));
    assert_eq!(restored.content_type, "text/plain");
    assert_eq!(restored.payload, b"hello droplet".to_vec());
    assert!(!restored.is_fallback);
}

#[test]
fn upload_restore_rejects_oversized_payload() {
    let snapshot = UploadStateSnapshot {
        file_name: Some("too-big.bin".to_owned()),
        content_type: "application/octet-stream".to_owned(),
        payload_hex: vec![0u8; MAX_UPLOAD_BYTES + 1].to_hex(),
        is_fallback: false,
    };

    let err = UploadState::restore(snapshot).expect_err("oversized upload should fail");
    assert!(err.contains("byte limit"));
}

#[test]
fn set_upload_rejects_oversized_payloads() {
    let app = DropletboxApp::new().expect("app should construct");
    let request = SetUploadRequest {
        file_name: Some("too-big.bin".to_owned()),
        content_type: Some("application/octet-stream".to_owned()),
        payload_bytes: vec![0u8; MAX_UPLOAD_BYTES + 1],
    };

    let err = app
        .apply_upload_request(request)
        .expect_err("oversized upload should fail");
    assert!(err.contains("byte limit"));
}

#[test]
fn fallback_upload_preview_exposes_text_and_payload_hex() {
    let preview = UploadState::fallback().preview_view();

    assert_eq!(preview.content_type, "text/plain;charset=utf-8");
    assert_eq!(preview.payload_len, 4);
    assert_eq!(preview.text.as_deref(), Some("💧"));
    assert_eq!(preview.payload_hex, "f09f92a7");
    assert!(preview.is_fallback);
}

#[test]
fn app_snapshot_roundtrip_preserves_active_swap_and_prepared_txs() {
    let config = SwapConfig::mainnet();
    let (spec, wallet) = test_wallet();
    let (response, preimage) =
        reverse_response_fixture_for_claim_public_key(wallet.claim_public_key());
    let prepared = prepared_fixture(true, false);
    let display = swap_display_fixture(&spec, &wallet);
    let swap_script = SwapScript::reverse_from_swap_resp(
        Chain::Liquid(LiquidChain::Liquid),
        &response,
        wallet.claim_public_key(),
    )
    .expect("fixture response should build a liquid swap script");

    let state = AppState {
        config,
        liquid_genesis_hash: None,
        current_upload: UploadState::fallback(),
        inscription_spec: spec,
        wallet: wallet.clone(),
        active_swap: Some(ActiveReverseSwap {
            preimage,
            swap_id: response.id.clone(),
            display: display.clone(),
            upload: UploadState::fallback(),
            reverse_response: response.clone(),
            swap_script,
            last_status: Some("transaction.mempool".to_owned()),
            last_lockup_txid: Some("lockup-txid".to_owned()),
            prepared: Some(prepared.clone()),
            terminal_error: None,
        }),
    };

    let restored = AppState::restore(state.snapshot().expect("snapshot should serialize"))
        .expect("snapshot should restore");
    let restored_active = restored
        .active_swap
        .expect("restored state should keep active swap");
    let restored_prepared = restored_active
        .prepared
        .expect("restored state should keep prepared transactions");

    assert_eq!(
        restored.wallet.commit_address_string(),
        wallet.commit_address_string()
    );
    assert_eq!(restored_active.swap_id, response.id);
    assert_eq!(restored_active.display, display);
    assert_eq!(
        restored_active.last_status.as_deref(),
        Some("transaction.mempool")
    );
    assert_eq!(
        restored_active.last_lockup_txid.as_deref(),
        Some("lockup-txid")
    );
    assert_eq!(restored_prepared.commit_txid, prepared.commit_txid);
    assert_eq!(restored_prepared.reveal.txid, prepared.reveal.txid);
    assert_eq!(
        liquid_tx_to_hex(&restored_prepared.commit_tx),
        liquid_tx_to_hex(&prepared.commit_tx)
    );
    assert_eq!(
        liquid_tx_to_hex(&restored_prepared.reveal.tx),
        liquid_tx_to_hex(&prepared.reveal.tx)
    );
    assert_eq!(restored.current_upload.view().payload_len, 4);
    assert_eq!(restored_active.upload.view().payload_len, 4);
}

#[test]
fn legacy_swap_display_snapshot_backfills_invoice_timing() {
    let (spec, wallet) = test_wallet();
    let mut display = swap_display_fixture(&spec, &wallet);
    display.invoice_created_at_unix = None;
    display.invoice_expires_at_unix = None;
    display.invoice_expiry_secs = None;

    display.hydrate_invoice_timing();

    assert_eq!(display.invoice_created_at_unix, Some(1_496_314_658));
    assert_eq!(display.invoice_expires_at_unix, Some(1_496_314_718));
    assert_eq!(display.invoice_expiry_secs, Some(60));
}

#[test]
fn active_swap_destination_uses_the_stored_destination_address() {
    let (spec, wallet) = test_wallet();
    let (response, preimage) =
        reverse_response_fixture_for_claim_public_key(wallet.claim_public_key());
    let swap_script = SwapScript::reverse_from_swap_resp(
        Chain::Liquid(LiquidChain::Liquid),
        &response,
        wallet.claim_public_key(),
    )
    .expect("fixture response should build a liquid swap script");
    let mut display = swap_display_fixture(&spec, &wallet);
    display.destination_address = CUSTOM_DESTINATION_ADDRESS.to_owned();
    let active_swap = ActiveReverseSwap {
        preimage,
        swap_id: response.id.clone(),
        display,
        upload: UploadState::fallback(),
        reverse_response: response,
        swap_script,
        last_status: Some("swap.created".to_owned()),
        last_lockup_txid: None,
        prepared: None,
        terminal_error: None,
    };

    let destination =
        destination_address_from_active_swap(&active_swap).expect("stored address should parse");

    assert_eq!(destination.to_string(), CUSTOM_DESTINATION_ADDRESS);
}

#[test]
fn unsupported_old_snapshot_version_is_rejected() {
    let snapshot = AppSnapshot {
        version: APP_SNAPSHOT_VERSION - 1,
        wallet: SessionWalletSnapshot {
            claim_secret_key_hex:
                "0101010101010101010101010101010101010101010101010101010101010101".to_owned(),
            inscription_secret_key_hex:
                "0202020202020202020202020202020202020202020202020202020202020202".to_owned(),
            commit_blinding_secret_key_hex:
                "0303030303030303030303030303030303030303030303030303030303030303".to_owned(),
        },
        current_upload: None,
        active_swap: None,
    };

    let err = AppState::restore(snapshot)
        .err()
        .expect("old snapshot version should fail");

    assert!(err.contains("Unsupported snapshot version"));
}

#[test]
fn status_mapping_covers_core_reverse_swap_states() {
    let building = build_status_view(
        Some("swap-id"),
        Some("transaction.mempool"),
        Some("lockup"),
        None,
        None,
        None,
    );
    assert_eq!(building.phase, "building_transactions");
    assert!(!building.is_terminal);

    let commit_built = build_status_view(
        Some("swap-id"),
        Some("transaction.confirmed"),
        Some("lockup"),
        Some(&prepared_fixture(false, false)),
        None,
        None,
    );
    assert_eq!(commit_built.phase, "commit_built");
    assert!(commit_built.commit_tx_hex.is_some());
    assert!(commit_built.reveal_tx_hex.is_some());

    let complete = build_status_view(
        Some("swap-id"),
        Some("transaction.mempool"),
        Some("lockup"),
        Some(&prepared_fixture(true, true)),
        None,
        None,
    );
    assert_eq!(complete.phase, "complete");
    assert!(complete.is_terminal);

    let invoice_paid = build_status_view(
        Some("swap-id"),
        Some("invoice.settled"),
        Some("lockup"),
        None,
        None,
        None,
    );
    assert_eq!(invoice_paid.phase, "invoice_paid");
    assert!(!invoice_paid.is_terminal);
    assert_eq!(
        invoice_paid.message,
        "Waiting to prepare commit and reveal transactions."
    );

    let invoice_expired = build_status_view(
        Some("swap-id"),
        Some("invoice.expired"),
        None,
        None,
        None,
        None,
    );
    assert_eq!(invoice_expired.phase, "invoice_expired");
    assert!(invoice_expired.is_terminal);

    let client_failed = build_status_view(
        Some("swap-id"),
        Some("transaction.confirmed"),
        Some("lockup"),
        Some(&prepared_fixture(true, false)),
        Some("reveal failed"),
        None,
    );
    assert_eq!(client_failed.phase, "client_failed");
    assert!(client_failed.is_terminal);
}

#[test]
fn derive_processing_step_covers_prepare_commit_and_reveal_transitions() {
    assert_eq!(
        derive_processing_step("invoice.settled", None, None, None, false),
        SwapProcessingStep::WaitForLockup
    );
    assert_eq!(
        derive_processing_step("invoice.settled", None, None, Some("lockup"), true),
        SwapProcessingStep::PrepareTransactions
    );
    assert_eq!(
        derive_processing_step(
            "transaction.confirmed",
            Some(&prepared_fixture(false, false)),
            None,
            Some("lockup"),
            true,
        ),
        SwapProcessingStep::BroadcastCommit
    );
    assert_eq!(
        derive_processing_step(
            "transaction.confirmed",
            Some(&prepared_fixture(true, false)),
            None,
            Some("lockup"),
            true,
        ),
        SwapProcessingStep::BroadcastReveal
    );
}

#[test]
fn build_status_view_uses_short_waiting_messages_for_processing_states() {
    let commit_ready = build_status_view(
        Some("swap-id"),
        Some("transaction.confirmed"),
        Some("lockup"),
        Some(&prepared_fixture(false, false)),
        None,
        None,
    );
    assert_eq!(
        commit_ready.message,
        "Commit and reveal transactions are ready. Waiting to broadcast commit."
    );

    let reveal_ready = build_status_view(
        Some("swap-id"),
        Some("transaction.confirmed"),
        Some("lockup"),
        Some(&prepared_fixture(true, false)),
        None,
        None,
    );
    assert_eq!(
        reveal_ready.message,
        "Waiting for commit output before broadcasting reveal."
    );
}

#[test]
fn lockup_wait_message_is_short_and_wait_focused() {
    assert_eq!(
        lockup_wait_message("invoice.settled", Some("lockup-txid")),
        "Lightning invoice paid. Waiting for Boltz lockup transaction details."
    );
    assert_eq!(
        lockup_wait_message("invoice.settled", None),
        "Lightning invoice paid. Waiting for Boltz lockup transaction."
    );
}

#[test]
fn derive_processing_step_stops_on_terminal_or_complete_states() {
    assert_eq!(
        derive_processing_step(
            "transaction.confirmed",
            Some(&prepared_fixture(true, false)),
            Some("boom"),
            Some("lockup"),
            true,
        ),
        SwapProcessingStep::NoOp
    );
    assert_eq!(
        derive_processing_step(
            "swap.created",
            Some(&prepared_fixture(false, false)),
            None,
            Some("lockup"),
            true,
        ),
        SwapProcessingStep::NoOp
    );
    assert_eq!(
        derive_processing_step(
            "transaction.confirmed",
            Some(&prepared_fixture(true, true)),
            None,
            Some("lockup"),
            true,
        ),
        SwapProcessingStep::NoOp
    );
}

#[test]
fn processing_guard_is_idempotent_once_reveal_is_done_or_failed() {
    assert!(should_process_swap("transaction.mempool", None, None));
    assert!(should_process_swap("transaction.confirmed", None, None));
    assert!(should_process_swap("invoice.settled", None, None));
    assert!(!should_process_swap(
        "transaction.mempool",
        Some(&prepared_fixture(true, true)),
        None,
    ));
    assert!(!should_process_swap(
        "transaction.confirmed",
        Some(&prepared_fixture(true, false)),
        Some("boom"),
    ));
}

#[test]
fn retry_outcome_discards_unseen_commit_and_keeps_visible_commit() {
    let unseen = retry_swap_outcome(Some(prepared_fixture(true, false)), false);
    assert!(unseen.prepared.is_none());
    assert!(unseen.message.contains("not visible"));

    let visible = retry_swap_outcome(Some(prepared_fixture(true, false)), true);
    assert!(visible.prepared.is_some());
    assert!(visible.message.contains("Keeping existing commit"));
}

#[test]
fn retry_outcome_discards_unbroadcast_prepared_transactions() {
    let outcome = retry_swap_outcome(Some(prepared_fixture(false, false)), false);
    assert!(outcome.prepared.is_none());
    assert!(outcome.message.contains("Discarded unbroadcast"));
}

#[test]
fn retryable_processing_status_matches_liquid_lockup_states() {
    assert!(is_retriable_processing_status("transaction.mempool"));
    assert!(is_retriable_processing_status("transaction.confirmed"));
    assert!(is_retriable_processing_status("invoice.settled"));
    assert!(!is_retriable_processing_status("swap.created"));
    assert!(!is_retriable_processing_status("invoice.expired"));
}

#[test]
fn manual_retry_rebuilds_reveal_when_commit_is_visible() {
    assert!(should_rebuild_reveal_on_retry(
        &prepared_fixture(true, false),
        true
    ));
    assert!(should_rebuild_reveal_on_retry(
        &prepared_fixture(true, true),
        true
    ));
    assert!(!should_rebuild_reveal_on_retry(
        &prepared_fixture(true, false),
        false
    ));
    assert!(!should_rebuild_reveal_on_retry(
        &prepared_fixture(false, true),
        true
    ));
}

#[test]
fn lockup_wait_errors_are_treated_as_retryable() {
    assert!(is_lockup_wait_error(
        "Esplora could not find a Liquid UTXO for script"
    ));
    assert!(is_lockup_wait_error(
        "No transaction hex found in boltz response"
    ));
    assert!(!is_lockup_wait_error("something else"));
}

#[test]
fn lockup_wait_message_prefers_paid_language_and_known_txid() {
    let paid = lockup_wait_message("invoice.settled", Some("lockup-txid"));
    assert_eq!(
        paid,
        "Lightning invoice paid. Waiting for Boltz lockup transaction details."
    );

    let funded = lockup_wait_message("transaction.mempool", Some("lockup-txid"));
    assert_eq!(funded, "Swap funded. Waiting for Boltz lockup transaction details.");
}

#[test]
fn lockup_txid_is_derived_from_hex_when_boltz_id_is_blank() {
    let prepared = prepared_fixture(false, false);
    let commit_tx_hex = liquid_tx_to_hex(&prepared.commit_tx);
    let expected_txid = prepared.commit_tx.txid().to_string();
    let response = boltz_client::boltz::GetSwapResponse {
        status: "transaction.mempool".to_owned(),
        zero_conf_rejected: None,
        transaction: Some(boltz_client::boltz::TransactionResponse {
            id: String::new(),
            hex: commit_tx_hex,
        }),
    };
    let parsed = lockup_tx_from_response(Chain::Liquid(LiquidChain::Liquid), &response)
        .expect("fixture tx should parse");

    let derived = lockup_txid_from_response(
        Chain::Liquid(LiquidChain::Liquid),
        &response,
        parsed.as_ref(),
    )
    .expect("lockup txid should derive");

    assert_eq!(derived.as_deref(), Some(expected_txid.as_str()));
}

#[test]
fn reverse_lockup_txid_is_derived_from_hex_when_reverse_id_is_blank() {
    let prepared = prepared_fixture(false, false);
    let commit_tx_hex = liquid_tx_to_hex(&prepared.commit_tx);
    let expected_txid = prepared.commit_tx.txid().to_string();
    let response = boltz_client::boltz::ReverseSwapTxResp {
        id: String::new(),
        hex: Some(commit_tx_hex),
        timeout_block_height: 1,
    };
    let parsed = reverse_lockup_tx_from_response(Chain::Liquid(LiquidChain::Liquid), &response)
        .expect("fixture tx should parse");

    let derived = lockup_txid_from_reverse_response(
        Chain::Liquid(LiquidChain::Liquid),
        &response,
        parsed.as_ref(),
    );

    assert_eq!(derived.as_deref(), Some(expected_txid.as_str()));
}

#[test]
fn transient_commit_visibility_errors_are_recoverable() {
    assert!(is_transient_commit_visibility_error_message(
        "I/O error: failed to fill whole buffer"
    ));
    assert!(is_transient_commit_visibility_error_message(
        "HTTP error: operation timed out"
    ));
    assert!(is_transient_commit_visibility_error_message(
        "HTTP error: 429 Too Many Requests"
    ));
    assert!(!is_transient_commit_visibility_error_message(
        "Esplora could not find a Liquid UTXO for script"
    ));
    assert!(!is_transient_commit_visibility_error_message(
        "No blinding key in tx."
    ));
}

#[test]
fn rate_limit_errors_are_retryable() {
    assert!(is_rate_limited_error_message(
        "HTTP error: 429 Too Many Requests"
    ));
    assert!(is_rate_limited_error_message(
        "request failed with status code 429"
    ));
    assert!(!is_rate_limited_error_message(
        "sendrawtransaction RPC error -25: bad-txns-inputs-missingorspent"
    ));
}

#[test]
fn missing_or_spent_input_errors_are_retryable() {
    assert!(is_missing_or_spent_input_error_message(
        "sendrawtransaction RPC error -25: bad-txns-inputs-missingorspent"
    ));
    assert!(is_missing_or_spent_input_error_message(
        "Inputs-MissingOrSpent while broadcasting"
    ));
    assert!(!is_missing_or_spent_input_error_message(
        "sendrawtransaction RPC error -26: min relay fee not met"
    ));
}

#[test]
fn missing_liquid_utxo_error_is_treated_as_wait_state() {
    assert!(is_missing_liquid_utxo_error(
        &boltz_client::error::Error::Protocol(
            "Esplora could not find a Liquid UTXO for script".to_owned()
        )
    ));
    assert!(!is_missing_liquid_utxo_error(
        &boltz_client::error::Error::Protocol("something else".to_owned())
    ));
}
