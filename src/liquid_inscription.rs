use boltz_client::{
    bitcoin::{hashes::Hash, key::rand::rngs::OsRng},
    elements::{
        self, Address, AddressParams, BlockHash, LockTime, OutPoint, RangeProofMessage, SchnorrSig,
        SchnorrSighashType, Script, Sequence, Transaction, TxIn, TxInWitness, TxOut, TxOutSecrets,
        TxOutWitness, Txid,
        confidential::{Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor},
        hex::ToHex,
        opcodes::{
            self,
            all::{OP_CHECKSIG, OP_ENDIF, OP_IF},
        },
        script::Builder,
        secp256k1_zkp::{All, Keypair as ZkKeypair, Message, Secp256k1, SecretKey},
        sighash::{Prevouts, SighashCache},
        taproot::{LeafVersion, TapLeafHash, TaprootBuilder, TaprootSpendInfo},
    },
    network::LiquidChain,
};
use serde::Serialize;
use std::str::FromStr;

const LIQUID_INSCRIPTION_CHUNK_BYTES: usize = 520;
const LIQUID_TX_VERSION: u32 = 2;
const DROPLET_PROTOCOL_ID: &[u8] = b"droplet";
#[cfg(test)]
const FALLBACK_CONTENT_TYPE: &[u8] = b"text/plain;charset=utf-8";
#[cfg(test)]
const FALLBACK_PAYLOAD: &str = "\u{1F4A7}";
const REVEAL_PREFIX_LEN: usize = 2;
const REVEAL_TARGET_PREFIX: [u8; REVEAL_PREFIX_LEN] = [0xb0, 0x0b];
const ESTIMATED_REVEAL_INPUT_SAT: u64 = 10_000;
const MAX_REVEAL_FEE_CONVERGENCE_PASSES: usize = 4;
const LIQUID_RELAY_SAFETY_BUFFER_SAT: u64 = 1;
const LIQUID_MAX_STANDARD_WEIGHT: usize = 400_000;
const DEFAULT_DESTINATION_ADDRESS: &str = "VJLGxsik4aRC4VjKt26BD5uj9t4UoaxMEXssnKNZ6o9DB9StfpzVGCKNUZCEBiGorzNdFZv1CbVEH1M6";

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct RevealFeePolicy {
    pub(crate) target_sat_per_vb: f64,
    pub(crate) relay_min_sat_per_vb: f64,
    pub(crate) safety_buffer_sat: u64,
    pub(crate) max_convergence_passes: usize,
}

impl RevealFeePolicy {
    pub(crate) fn new(target_sat_per_vb: f64, relay_min_sat_per_vb: f64) -> Self {
        Self {
            target_sat_per_vb,
            relay_min_sat_per_vb,
            safety_buffer_sat: LIQUID_RELAY_SAFETY_BUFFER_SAT,
            max_convergence_passes: MAX_REVEAL_FEE_CONVERGENCE_PASSES,
        }
    }

    fn effective_sat_per_vb(&self) -> f64 {
        self.target_sat_per_vb.max(self.relay_min_sat_per_vb)
    }
}

pub(crate) struct RevealContext<'a> {
    pub(crate) chain: LiquidChain,
    pub(crate) spec: &'a InscriptionSpec,
    pub(crate) destination: &'a Address,
    pub(crate) genesis_hash: BlockHash,
    pub(crate) commit_txid: Txid,
    pub(crate) commit_output: &'a TxOut,
}

struct RevealBuildContext<'a> {
    secp: &'a Secp256k1<All>,
    commit_txid: Txid,
    input_secrets: &'a TxOutSecrets,
    destination: &'a Address,
    commit_output: &'a TxOut,
    artifacts: &'a InscriptionArtifacts,
    inscription_keypair: &'a ZkKeypair,
    genesis_hash: BlockHash,
}

#[derive(Clone)]
pub(crate) struct InscriptionSpec {
    pub(crate) payload: Vec<u8>,
    pub(crate) content_type: Vec<u8>,
    pub(crate) protocol_id: Option<Vec<u8>>,
    pub(crate) default_destination_address: Address,
    pub(crate) reveal_target_prefix: [u8; REVEAL_PREFIX_LEN],
}

impl InscriptionSpec {
    #[cfg(test)]
    pub(crate) fn mainnet() -> Result<Self, String> {
        Self::mainnet_with_payload(
            FALLBACK_PAYLOAD.as_bytes().to_vec(),
            FALLBACK_CONTENT_TYPE.to_vec(),
        )
    }

    pub(crate) fn mainnet_with_payload(
        payload: Vec<u8>,
        content_type: Vec<u8>,
    ) -> Result<Self, String> {
        let default_destination_address =
            parse_confidential_destination_address(DEFAULT_DESTINATION_ADDRESS)?;

        Ok(Self {
            payload,
            content_type,
            protocol_id: Some(DROPLET_PROTOCOL_ID.to_vec()),
            default_destination_address,
            reveal_target_prefix: derive_reveal_target_prefix(),
        })
    }
    pub(crate) fn destination_address_string(&self) -> String {
        self.default_destination_address.to_string()
    }

    pub(crate) fn reveal_target_prefix_hex(&self) -> String {
        prefix_to_hex(&self.reveal_target_prefix)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DecodedRevealPayload {
    pub(crate) protocol_id: String,
    pub(crate) content_type: String,
    pub(crate) payload_hex: String,
    pub(crate) payload_len: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) text: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedRevealEnvelope {
    protocol_id: Vec<u8>,
    content_type: Vec<u8>,
    payload: Vec<u8>,
}

pub(crate) fn parse_confidential_destination_address(address: &str) -> Result<Address, String> {
    let destination_address = Address::parse_with_params(address, &AddressParams::LIQUID)
        .map_err(|err| format!("Invalid Liquid address: {err}"))?;
    if !destination_address.is_blinded() {
        return Err("Destination address must be a confidential Liquid address.".to_owned());
    }

    Ok(destination_address)
}

#[derive(Clone)]
pub(crate) struct InscriptionWallet {
    inscription_keypair: ZkKeypair,
    commit_blinding_key: ZkKeypair,
    artifacts: InscriptionArtifacts,
}

impl InscriptionWallet {
    pub(crate) fn generate(chain: LiquidChain, spec: &InscriptionSpec) -> Result<Self, String> {
        let secp = Secp256k1::new();
        let mut rng = OsRng;

        let inscription_secret = SecretKey::new(&mut rng);
        let commit_blinding_secret = SecretKey::new(&mut rng);
        let inscription_keypair = ZkKeypair::from_secret_key(&secp, &inscription_secret);
        let commit_blinding_key = ZkKeypair::from_secret_key(&secp, &commit_blinding_secret);
        let artifacts = InscriptionArtifacts::new(
            &secp,
            &inscription_keypair,
            &commit_blinding_key,
            chain,
            spec,
        )?;

        Ok(Self {
            inscription_keypair,
            commit_blinding_key,
            artifacts,
        })
    }

    pub(crate) fn commit_address_string(&self) -> String {
        self.artifacts.commit_address.to_string()
    }

    pub(crate) fn commit_address(&self) -> &Address {
        &self.artifacts.commit_address
    }

    pub(crate) fn restore(
        chain: LiquidChain,
        spec: &InscriptionSpec,
        inscription_secret_key_hex: &str,
        commit_blinding_secret_key_hex: &str,
    ) -> Result<Self, String> {
        let secp = Secp256k1::new();
        let inscription_secret =
            SecretKey::from_str(inscription_secret_key_hex).map_err(|err| err.to_string())?;
        let commit_blinding_secret =
            SecretKey::from_str(commit_blinding_secret_key_hex).map_err(|err| err.to_string())?;
        let inscription_keypair = ZkKeypair::from_secret_key(&secp, &inscription_secret);
        let commit_blinding_key = ZkKeypair::from_secret_key(&secp, &commit_blinding_secret);
        let artifacts = InscriptionArtifacts::new(
            &secp,
            &inscription_keypair,
            &commit_blinding_key,
            chain,
            spec,
        )?;

        Ok(Self {
            inscription_keypair,
            commit_blinding_key,
            artifacts,
        })
    }

    pub(crate) fn inscription_secret_key_string(&self) -> String {
        self.inscription_keypair
            .secret_key()
            .display_secret()
            .to_string()
    }

    pub(crate) fn commit_blinding_secret_key_string(&self) -> String {
        self.commit_blinding_key
            .secret_key()
            .display_secret()
            .to_string()
    }

    pub(crate) fn estimate_reveal_fee_sats(
        &self,
        chain: LiquidChain,
        destination: &Address,
        genesis_hash: BlockHash,
        fee_rate_sat_per_vb: f64,
        relay_min_fee_rate_sat_per_vb: f64,
    ) -> Result<u64, String> {
        let secp = Secp256k1::new();
        let input_secrets = TxOutSecrets::new(
            chain.bitcoin(),
            AssetBlindingFactor::zero(),
            ESTIMATED_REVEAL_INPUT_SAT,
            ValueBlindingFactor::zero(),
        );
        let commit_output = explicit_output(
            chain.bitcoin(),
            input_secrets.value,
            self.artifacts.commit_script_pubkey.clone(),
        );
        let fee_policy = RevealFeePolicy::new(fee_rate_sat_per_vb, relay_min_fee_rate_sat_per_vb);
        let reveal_context = RevealBuildContext {
            secp: &secp,
            commit_txid: Txid::from_byte_array([0u8; 32]),
            input_secrets: &input_secrets,
            destination,
            commit_output: &commit_output,
            artifacts: &self.artifacts,
            inscription_keypair: &self.inscription_keypair,
            genesis_hash,
        };
        converged_reveal_fee_sats(&reveal_context, fee_policy)
    }

    pub(crate) fn prepare_reveal(
        &self,
        context: RevealContext<'_>,
        fee_policy: RevealFeePolicy,
    ) -> Result<PreparedReveal, String> {
        let secp = Secp256k1::new();
        let input_secrets = unblind_output(
            context.chain,
            context.commit_output,
            self.commit_blinding_key.secret_key(),
        )
        .map_err(|err| err.to_string())?;
        let reveal_context = RevealBuildContext {
            secp: &secp,
            commit_txid: context.commit_txid,
            input_secrets: &input_secrets,
            destination: context.destination,
            commit_output: context.commit_output,
            artifacts: &self.artifacts,
            inscription_keypair: &self.inscription_keypair,
            genesis_hash: context.genesis_hash,
        };
        let reveal_fee_sat = converged_reveal_fee_sats(&reveal_context, fee_policy)?;
        let reveal_amount_sat =
            input_secrets
                .value
                .checked_sub(reveal_fee_sat)
                .ok_or_else(|| {
                    format!(
                        "Commit output value {} sats is too small to cover the {} sat reveal fee",
                        input_secrets.value, reveal_fee_sat
                    )
                })?;
        if reveal_amount_sat == 0 {
            return Err("Reveal transaction would leave a zero-valued destination output".into());
        }

        let mut unsigned_reveal = build_unsigned_reveal_tx(
            &secp,
            context.commit_txid,
            &input_secrets,
            context.destination,
            reveal_fee_sat,
        )?;
        let grind_nonce =
            grind_reveal_locktime(&mut unsigned_reveal, &context.spec.reveal_target_prefix)?;
        let signed_reveal = sign_reveal_tx(
            &secp,
            unsigned_reveal,
            context.commit_output.clone(),
            &self.artifacts,
            &self.inscription_keypair,
            context.genesis_hash,
        )?;
        validate_reveal_weight(&signed_reveal)?;
        let txid = signed_reveal.txid();
        let exact_fee_sat = fee_sats_from_rate(signed_reveal.discount_vsize() as u64, fee_policy)?;
        if exact_fee_sat != reveal_fee_sat {
            return Err(format!(
                "Reveal fee did not converge: built with {} sats, but final size requires {} sats.",
                reveal_fee_sat, exact_fee_sat
            ));
        }
        if !displayed_txid_matches_prefix(&txid, &context.spec.reveal_target_prefix) {
            return Err("Reveal txid no longer matches the target prefix after signing.".into());
        }

        Ok(PreparedReveal {
            tx: signed_reveal,
            txid: txid.to_string(),
            fee_sat: reveal_fee_sat,
            output_amount_sat: reveal_amount_sat,
            target_prefix_hex: context.spec.reveal_target_prefix_hex(),
            grind_nonce,
        })
    }
}

#[derive(Clone)]
pub(crate) struct InscriptionArtifacts {
    tapscript: Script,
    spend_info: TaprootSpendInfo,
    pub(crate) commit_address: Address,
    commit_script_pubkey: Script,
}

impl InscriptionArtifacts {
    fn new(
        secp: &Secp256k1<All>,
        inscription_keypair: &ZkKeypair,
        commit_blinding_key: &ZkKeypair,
        chain: LiquidChain,
        spec: &InscriptionSpec,
    ) -> Result<Self, String> {
        let (internal_key, _) = inscription_keypair.x_only_public_key();
        let tapscript = build_inscription_script(
            internal_key,
            spec.protocol_id.as_deref(),
            &spec.content_type,
            &spec.payload,
        );
        let spend_info = TaprootBuilder::new()
            .add_leaf(0, tapscript.clone())
            .map_err(|err| err.to_string())?
            .finalize(secp, internal_key)
            .map_err(|err| err.to_string())?;
        let commit_address = Address::p2tr(
            secp,
            internal_key,
            spend_info.merkle_root(),
            Some(commit_blinding_key.public_key()),
            chain.into(),
        );
        let commit_script_pubkey = commit_address.script_pubkey();

        Ok(Self {
            tapscript,
            spend_info,
            commit_address,
            commit_script_pubkey,
        })
    }
}

#[derive(Clone, Debug)]
pub(crate) struct PreparedReveal {
    pub(crate) tx: Transaction,
    pub(crate) txid: String,
    pub(crate) fee_sat: u64,
    pub(crate) output_amount_sat: u64,
    pub(crate) target_prefix_hex: String,
    #[allow(dead_code)]
    pub(crate) grind_nonce: u32,
}

pub(crate) fn derive_reveal_target_prefix() -> [u8; REVEAL_PREFIX_LEN] {
    REVEAL_TARGET_PREFIX
}

pub(crate) fn decode_reveal_payload(tx: &Transaction) -> Result<DecodedRevealPayload, String> {
    let tapscript_bytes = tx
        .input
        .first()
        .and_then(|input| input.witness.script_witness.get(1))
        .ok_or_else(|| "Reveal transaction is missing its tapscript witness.".to_owned())?;
    let tapscript = Script::from(tapscript_bytes.clone());
    let envelope = extract_reveal_envelope_from_tapscript(&tapscript)?;
    let protocol_id = String::from_utf8(envelope.protocol_id.clone())
        .map_err(|err| format!("Reveal protocol id is not valid UTF-8: {err}"))?;
    let content_type = String::from_utf8(envelope.content_type.clone())
        .map_err(|err| format!("Reveal content type is not valid UTF-8: {err}"))?;
    let text = String::from_utf8(envelope.payload.clone()).ok();

    Ok(DecodedRevealPayload {
        protocol_id,
        content_type,
        payload_hex: envelope.payload.to_hex(),
        payload_len: envelope.payload.len(),
        text,
    })
}

fn prefix_to_hex(prefix: &[u8; REVEAL_PREFIX_LEN]) -> String {
    format!("{:02x}{:02x}", prefix[0], prefix[1])
}

fn build_inscription_script(
    x_only_pubkey: elements::secp256k1_zkp::XOnlyPublicKey,
    protocol_id: Option<&[u8]>,
    content_type: &[u8],
    payload: &[u8],
) -> Script {
    let mut builder = Builder::new()
        .push_slice(&x_only_pubkey.serialize())
        .push_opcode(OP_CHECKSIG)
        .push_opcode(opcodes::OP_FALSE)
        .push_opcode(OP_IF);

    if let Some(protocol_id) = protocol_id {
        builder = builder.push_slice(protocol_id);
    }

    builder = builder
        .push_slice(&[1])
        .push_slice(content_type)
        .push_slice(&[]);

    for chunk in payload.chunks(LIQUID_INSCRIPTION_CHUNK_BYTES) {
        builder = builder.push_slice(chunk);
    }

    builder.push_opcode(OP_ENDIF).into_script()
}

fn extract_reveal_envelope_from_tapscript(
    tapscript: &Script,
) -> Result<ParsedRevealEnvelope, String> {
    let instructions = tapscript
        .instructions()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| err.to_string())?;
    if instructions.len() < 9 {
        return Err("Reveal tapscript is shorter than expected.".to_owned());
    }
    let protocol_id = instructions[4]
        .push_bytes()
        .ok_or_else(|| "Reveal tapscript is missing the droplet protocol id.".to_owned())?;
    if protocol_id != DROPLET_PROTOCOL_ID {
        return Err("Reveal tapscript protocol id must be droplet.".to_owned());
    }
    if instructions[5].push_bytes() != Some([1].as_slice()) {
        return Err("Reveal tapscript is missing the inscription content marker.".to_owned());
    }
    let content_type = instructions[6]
        .push_bytes()
        .ok_or_else(|| "Reveal tapscript is missing the content type.".to_owned())?;
    if content_type.is_empty() {
        return Err("Reveal tapscript content type cannot be empty.".to_owned());
    }
    if instructions[7].push_bytes() != Some([].as_slice()) {
        return Err("Reveal tapscript is missing the payload separator.".to_owned());
    }

    let mut payload = Vec::new();
    let mut saw_end_if = false;
    for instruction in instructions.iter().skip(8) {
        if instruction.op() == Some(OP_ENDIF) {
            saw_end_if = true;
            break;
        }

        let chunk = instruction
            .push_bytes()
            .ok_or_else(|| "Reveal tapscript payload contains an unexpected opcode.".to_owned())?;
        payload.extend_from_slice(chunk);
    }

    if !saw_end_if {
        return Err("Reveal tapscript payload does not terminate with OP_ENDIF.".to_owned());
    }

    Ok(ParsedRevealEnvelope {
        protocol_id: protocol_id.to_vec(),
        content_type: content_type.to_vec(),
        payload,
    })
}

fn validate_reveal_weight(tx: &Transaction) -> Result<(), String> {
    if tx.weight() > LIQUID_MAX_STANDARD_WEIGHT {
        return Err(format!(
            "Liquid inscription reveal exceeds the standard transaction weight limit: {} wu > {} wu",
            tx.weight(),
            LIQUID_MAX_STANDARD_WEIGHT
        ));
    }

    Ok(())
}

fn explicit_output(asset_id: elements::AssetId, value_sat: u64, script_pubkey: Script) -> TxOut {
    TxOut {
        asset: Asset::Explicit(asset_id),
        value: Value::Explicit(value_sat),
        nonce: Nonce::Null,
        script_pubkey,
        witness: TxOutWitness::default(),
    }
}

fn unblind_output(
    chain: LiquidChain,
    output: &TxOut,
    blinding_key: SecretKey,
) -> Result<TxOutSecrets, String> {
    let secp = Secp256k1::new();
    let secrets = output
        .unblind(&secp, blinding_key)
        .map_err(|err| err.to_string())?;
    if secrets.asset != chain.bitcoin() {
        return Err(format!(
            "Expected L-BTC commit output, found asset {}",
            secrets.asset
        ));
    }
    Ok(secrets)
}

fn converged_reveal_fee_sats(
    context: &RevealBuildContext<'_>,
    fee_policy: RevealFeePolicy,
) -> Result<u64, String> {
    let mut reveal_fee_sat = fee_sats_from_rate(
        {
            let signed_reveal = build_signed_reveal_tx_with_fee(context, 0)?;
            validate_reveal_weight(&signed_reveal)?;
            signed_reveal
        }
        .discount_vsize() as u64,
        fee_policy,
    )?;

    for _ in 0..fee_policy.max_convergence_passes {
        let signed_reveal = build_signed_reveal_tx_with_fee(context, reveal_fee_sat)?;
        validate_reveal_weight(&signed_reveal)?;
        let exact_fee_sat = fee_sats_from_rate(signed_reveal.discount_vsize() as u64, fee_policy)?;
        if exact_fee_sat == reveal_fee_sat {
            return Ok(reveal_fee_sat);
        }
        reveal_fee_sat = exact_fee_sat;
    }

    Err(format!(
        "Reveal fee did not converge after {} passes.",
        fee_policy.max_convergence_passes
    ))
}

fn fee_sats_from_rate(vbytes: u64, fee_policy: RevealFeePolicy) -> Result<u64, String> {
    if !fee_policy.target_sat_per_vb.is_finite() || fee_policy.target_sat_per_vb <= 0.0 {
        return Err(format!(
            "Liquid fee rate must be positive and finite, got {}",
            fee_policy.target_sat_per_vb
        ));
    }

    if !fee_policy.relay_min_sat_per_vb.is_finite() || fee_policy.relay_min_sat_per_vb <= 0.0 {
        return Err(format!(
            "Liquid relay minimum fee rate must be positive and finite, got {}",
            fee_policy.relay_min_sat_per_vb
        ));
    }

    let fee_sat = (vbytes as f64 * fee_policy.effective_sat_per_vb()).ceil();
    if !fee_sat.is_finite() || fee_sat > u64::MAX as f64 {
        return Err("Reveal fee calculation overflowed.".into());
    }

    (fee_sat as u64)
        .checked_add(fee_policy.safety_buffer_sat)
        .ok_or_else(|| "Reveal fee calculation overflowed.".to_owned())
}

fn build_signed_reveal_tx_with_fee(
    context: &RevealBuildContext<'_>,
    fee_sat: u64,
) -> Result<Transaction, String> {
    let unsigned_reveal = build_unsigned_reveal_tx(
        context.secp,
        context.commit_txid,
        context.input_secrets,
        context.destination,
        fee_sat,
    )?;
    sign_reveal_tx(
        context.secp,
        unsigned_reveal,
        context.commit_output.clone(),
        context.artifacts,
        context.inscription_keypair,
        context.genesis_hash,
    )
}

fn build_blinded_payment_output(
    secp: &Secp256k1<All>,
    input_secrets: &TxOutSecrets,
    destination: &Address,
    amount_sat: u64,
    fee_sat: u64,
) -> Result<TxOut, String> {
    let mut rng = OsRng;
    let output_abf = AssetBlindingFactor::new(&mut rng);
    let asset = Asset::Explicit(input_secrets.asset);
    let (blinded_asset, surjection_proof) = asset
        .blind(
            &mut rng,
            secp,
            output_abf,
            std::slice::from_ref(input_secrets),
        )
        .map_err(|err| err.to_string())?;

    let final_vbf = ValueBlindingFactor::last(
        secp,
        amount_sat,
        output_abf,
        &[input_secrets.value_blind_inputs()],
        &[(
            fee_sat,
            AssetBlindingFactor::zero(),
            ValueBlindingFactor::zero(),
        )],
    );
    let explicit_value = Value::Explicit(amount_sat);
    let blinding_pubkey = destination
        .blinding_pubkey
        .ok_or_else(|| "Destination address is not blinded.".to_owned())?;
    let ephemeral_sk = SecretKey::new(&mut rng);
    let message = RangeProofMessage {
        asset: input_secrets.asset,
        bf: output_abf,
    };
    let (blinded_value, nonce, rangeproof) = explicit_value
        .blind(
            secp,
            final_vbf,
            blinding_pubkey,
            ephemeral_sk,
            &destination.script_pubkey(),
            &message,
        )
        .map_err(|err| err.to_string())?;

    Ok(TxOut {
        script_pubkey: destination.script_pubkey(),
        value: blinded_value,
        asset: blinded_asset,
        nonce,
        witness: TxOutWitness {
            surjection_proof: Some(Box::new(surjection_proof)),
            rangeproof: Some(Box::new(rangeproof)),
        },
    })
}

fn build_unsigned_reveal_tx(
    secp: &Secp256k1<All>,
    commit_txid: Txid,
    input_secrets: &TxOutSecrets,
    destination: &Address,
    fee_sat: u64,
) -> Result<Transaction, String> {
    let output_amount_sat = input_secrets.value.checked_sub(fee_sat).ok_or_else(|| {
        format!(
            "Commit output value {} sats is too small to cover the {} sat reveal fee",
            input_secrets.value, fee_sat
        )
    })?;
    if output_amount_sat == 0 {
        return Err("Reveal transaction would leave a zero-valued destination output".into());
    }

    let payment_output =
        build_blinded_payment_output(secp, input_secrets, destination, output_amount_sat, fee_sat)?;
    let fee_output = TxOut::new_fee(fee_sat, input_secrets.asset);

    Ok(Transaction {
        version: LIQUID_TX_VERSION,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(commit_txid, 0),
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: TxInWitness::default(),
            is_pegin: false,
            asset_issuance: elements::AssetIssuance::default(),
        }],
        output: vec![payment_output, fee_output],
    })
}

fn sign_reveal_tx(
    secp: &Secp256k1<All>,
    mut tx: Transaction,
    commit_output: TxOut,
    artifacts: &InscriptionArtifacts,
    inscription_keypair: &ZkKeypair,
    genesis_hash: BlockHash,
) -> Result<Transaction, String> {
    let leaf_version = LeafVersion::default();
    let leaf_hash = TapLeafHash::from_script(&artifacts.tapscript, leaf_version);
    let control_block = artifacts
        .spend_info
        .control_block(&(artifacts.tapscript.clone(), leaf_version))
        .ok_or_else(|| "Failed to derive Liquid taproot control block.".to_owned())?;

    let sighash = SighashCache::new(&tx)
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&[&commit_output]),
            leaf_hash,
            SchnorrSighashType::Default,
            genesis_hash,
        )
        .map_err(|err| err.to_string())?;

    let msg = Message::from_digest_slice(sighash.as_byte_array()).map_err(|err| err.to_string())?;
    let sig = secp.sign_schnorr_no_aux_rand(&msg, inscription_keypair);
    let witness = TxInWitness {
        amount_rangeproof: None,
        inflation_keys_rangeproof: None,
        script_witness: vec![
            SchnorrSig {
                sig,
                hash_ty: SchnorrSighashType::Default,
            }
            .to_vec(),
            artifacts.tapscript.to_bytes(),
            control_block.serialize(),
        ],
        pegin_witness: vec![],
    };
    tx.input[0].witness = witness;
    Ok(tx)
}

fn displayed_txid_matches_prefix(txid: &Txid, prefix: &[u8; REVEAL_PREFIX_LEN]) -> bool {
    let raw = txid.to_byte_array();
    raw[31] == prefix[0] && raw[30] == prefix[1]
}

fn grind_reveal_locktime(
    tx: &mut Transaction,
    prefix: &[u8; REVEAL_PREFIX_LEN],
) -> Result<u32, String> {
    if tx.input.is_empty() {
        return Err("Reveal transaction has no inputs.".into());
    }

    for nonce in 0..=u32::MAX {
        tx.lock_time = LockTime::from_consensus(nonce);
        if displayed_txid_matches_prefix(&tx.txid(), prefix) {
            return Ok(nonce);
        }
    }

    Err("Unable to grind a reveal txid prefix before exhausting the search space.".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    const CUSTOM_DESTINATION_ADDRESS: &str =
        "VJLGxsik4aRC4VjKt26BD5uj9t4UoaxMEXssnKNZ6o9DB9StfpzVGCKNUZCEBiGorzNdFZv1CbVEH1M6";

    fn test_wallet() -> InscriptionWallet {
        let secp = Secp256k1::new();
        let inscription_keypair = ZkKeypair::from_secret_key(
            &secp,
            &SecretKey::from_str(
                "0101010101010101010101010101010101010101010101010101010101010101",
            )
            .expect("valid secret"),
        );
        let commit_blinding_key = ZkKeypair::from_secret_key(
            &secp,
            &SecretKey::from_str(
                "0202020202020202020202020202020202020202020202020202020202020202",
            )
            .expect("valid secret"),
        );
        let spec = InscriptionSpec::mainnet().expect("spec should build");
        let artifacts = InscriptionArtifacts::new(
            &secp,
            &inscription_keypair,
            &commit_blinding_key,
            LiquidChain::Liquid,
            &spec,
        )
        .expect("artifacts should build");

        InscriptionWallet {
            inscription_keypair,
            commit_blinding_key,
            artifacts,
        }
    }

    fn dummy_commit_output(wallet: &InscriptionWallet, value_sat: u64) -> TxOut {
        let secp = Secp256k1::new();
        let input_secrets = TxOutSecrets::new(
            LiquidChain::Liquid.bitcoin(),
            AssetBlindingFactor::zero(),
            value_sat,
            ValueBlindingFactor::zero(),
        );

        build_blinded_payment_output(
            &secp,
            &input_secrets,
            &wallet.artifacts.commit_address,
            value_sat,
            0,
        )
        .expect("dummy commit output should build")
    }

    #[test]
    fn mainnet_destination_is_valid_confidential_liquid_address() {
        let spec = InscriptionSpec::mainnet().expect("spec should build");

        assert_eq!(
            spec.default_destination_address.to_string(),
            DEFAULT_DESTINATION_ADDRESS
        );
        assert!(spec.default_destination_address.is_blinded());
        assert_eq!(
            spec.default_destination_address.params,
            &AddressParams::LIQUID
        );
    }

    #[test]
    fn custom_destination_parser_rejects_unconfidential_addresses() {
        let default_destination =
            parse_confidential_destination_address(DEFAULT_DESTINATION_ADDRESS).expect("valid");
        let err = parse_confidential_destination_address(
            &default_destination.to_unconfidential().to_string(),
        )
        .expect_err("unconfidential address should fail");

        assert!(err.contains("confidential"));
    }

    #[test]
    fn tapscript_matches_expected_liquid_format_and_payload() {
        let wallet = test_wallet();
        let instructions = wallet
            .artifacts
            .tapscript
            .instructions()
            .collect::<Result<Vec<_>, _>>()
            .expect("tapscript should parse");

        assert_eq!(
            instructions[4]
                .push_bytes()
                .expect("protocol id should be push"),
            DROPLET_PROTOCOL_ID
        );
        assert_eq!(
            instructions[5]
                .push_bytes()
                .expect("content marker should be push"),
            [1]
        );
        assert_eq!(
            instructions[6]
                .push_bytes()
                .expect("content type should be push"),
            FALLBACK_CONTENT_TYPE
        );
        assert_eq!(
            instructions[7]
                .push_bytes()
                .expect("separator should be push"),
            b""
        );
        assert_eq!(
            instructions[8]
                .push_bytes()
                .expect("payload should be push"),
            FALLBACK_PAYLOAD.as_bytes()
        );
    }

    #[test]
    fn reveal_target_prefix_is_b00b() {
        let prefix = derive_reveal_target_prefix();

        assert_eq!(prefix, [0xb0, 0x0b]);
        assert_eq!(prefix_to_hex(&prefix), "b00b");
    }

    #[test]
    fn reveal_fee_respects_minimum_relay_rate() {
        let fee =
            fee_sats_from_rate(193, RevealFeePolicy::new(0.01, 0.1)).expect("fee should calculate");

        assert_eq!(fee, 21);
    }

    #[test]
    fn reveal_fee_tracks_tx_size_under_relay_minimum_rate() {
        let fee =
            fee_sats_from_rate(201, RevealFeePolicy::new(0.01, 0.1)).expect("fee should calculate");

        assert_eq!(fee, 22);
    }

    #[test]
    fn reveal_preparation_grinds_txid_and_preserves_payload_destination() {
        let wallet = test_wallet();
        let spec = InscriptionSpec::mainnet().expect("spec should build");
        let destination =
            parse_confidential_destination_address(CUSTOM_DESTINATION_ADDRESS).expect("valid");
        let commit_output = dummy_commit_output(&wallet, 5_000);
        let prepared = wallet
            .prepare_reveal(
                RevealContext {
                    chain: LiquidChain::Liquid,
                    spec: &spec,
                    destination: &destination,
                    genesis_hash: BlockHash::from_byte_array([3u8; 32]),
                    commit_txid: Txid::from_byte_array([4u8; 32]),
                    commit_output: &commit_output,
                },
                RevealFeePolicy::new(0.1, 0.1),
            )
            .expect("reveal should prepare");

        assert_eq!(prepared.target_prefix_hex, "b00b");
        assert!(prepared.txid.starts_with("b00b"));
        assert_eq!(prepared.tx.output.len(), 2);
        assert_eq!(
            prepared.tx.output[0].script_pubkey,
            destination.script_pubkey()
        );
    }

    #[test]
    fn reveal_construction_rejects_zero_value_destination() {
        let wallet = test_wallet();
        let spec = InscriptionSpec::mainnet().expect("spec should build");
        let destination =
            parse_confidential_destination_address(CUSTOM_DESTINATION_ADDRESS).expect("valid");
        let commit_output = dummy_commit_output(&wallet, 1);
        let err = wallet
            .prepare_reveal(
                RevealContext {
                    chain: LiquidChain::Liquid,
                    spec: &spec,
                    destination: &destination,
                    genesis_hash: BlockHash::from_byte_array([5u8; 32]),
                    commit_txid: Txid::from_byte_array([6u8; 32]),
                    commit_output: &commit_output,
                },
                RevealFeePolicy::new(1.0, 0.1),
            )
            .expect_err("reveal should reject zero-value output");

        assert!(err.contains("zero-valued destination output") || err.contains("too small"));
    }

    #[test]
    fn reveal_payload_decoder_extracts_the_droplet_emoji() {
        let wallet = test_wallet();
        let spec = InscriptionSpec::mainnet().expect("spec should build");
        let destination =
            parse_confidential_destination_address(CUSTOM_DESTINATION_ADDRESS).expect("valid");
        let commit_output = dummy_commit_output(&wallet, 5_000);
        let prepared = wallet
            .prepare_reveal(
                RevealContext {
                    chain: LiquidChain::Liquid,
                    spec: &spec,
                    destination: &destination,
                    genesis_hash: BlockHash::from_byte_array([7u8; 32]),
                    commit_txid: Txid::from_byte_array([8u8; 32]),
                    commit_output: &commit_output,
                },
                RevealFeePolicy::new(0.1, 0.1),
            )
            .expect("reveal should prepare");
        let decoded = decode_reveal_payload(&prepared.tx).expect("payload should decode");

        assert_eq!(decoded.protocol_id, "droplet");
        assert_eq!(decoded.content_type, "text/plain;charset=utf-8");
        assert_eq!(decoded.text.as_deref(), Some(FALLBACK_PAYLOAD));
        assert_eq!(decoded.payload_hex, FALLBACK_PAYLOAD.as_bytes().to_hex());
        assert_eq!(decoded.payload_len, FALLBACK_PAYLOAD.len());
    }

    #[test]
    fn reveal_payload_decoder_rejects_legacy_untagged_and_ord_envelopes() {
        let wallet = test_wallet();
        let (internal_key, _) = wallet.inscription_keypair.x_only_public_key();
        let legacy_tapscript = build_inscription_script(
            internal_key,
            None,
            b"text/plain",
            FALLBACK_PAYLOAD.as_bytes(),
        );
        let ord_tapscript = build_inscription_script(
            internal_key,
            Some(b"ord"),
            b"text/plain",
            FALLBACK_PAYLOAD.as_bytes(),
        );
        let mut tx = Transaction {
            version: LIQUID_TX_VERSION,
            lock_time: LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![],
        };

        tx.input[0].witness.script_witness = vec![vec![], legacy_tapscript.to_bytes()];
        let legacy_err = decode_reveal_payload(&tx).expect_err("legacy envelope should fail");
        assert!(legacy_err.contains("protocol id"));

        tx.input[0].witness.script_witness = vec![vec![], ord_tapscript.to_bytes()];
        let ord_err = decode_reveal_payload(&tx).expect_err("ord envelope should fail");
        assert!(ord_err.contains("droplet"));
    }
}
