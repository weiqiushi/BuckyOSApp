use bip39::{Language, Mnemonic};
use rand::{rngs::OsRng, RngCore};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use tauri::AppHandle;

use crate::error::{CommandErrors, CommandResult};

use super::crypto::{decrypt_mnemonic, encrypt_mnemonic};
use super::domain::{BtcAddressType, DidInfo, SnStatusInfo};
use super::identity::{derive_wallets_with_requests, DidDerivationPlan, WalletRequest};
use super::store::{load_vault, new_did_id, open_store, save_vault, StoredDid};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use secrecy::{ExposeSecret, SecretString};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(test)]
use super::derive::{derive_eth_address, SeedCtx};

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WalletExtensionKind {
    Btc {
        address_type: BtcAddressType,
        #[serde(default = "default_count")]
        count: u32,
    },
    Eth {
        #[serde(default = "default_count")]
        count: u32,
    },
    Bucky {
        #[serde(default = "default_count")]
        count: u32,
    },
}

fn default_count() -> u32 {
    1
}

#[tauri::command]
pub fn generate_mnemonic() -> CommandResult<Vec<String>> {
    let mut entropy = [0u8; 16]; // 128 bits for 12 words
    OsRng.fill_bytes(&mut entropy);
    let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)?;
    Ok(mnemonic
        .to_string()
        .split_whitespace()
        .map(|s| s.to_string())
        .collect())
}

#[tauri::command]
pub fn validate_mnemonic_words(words: Vec<String>) -> CommandResult<Option<String>> {
    for word in words {
        let trimmed = word.trim();
        if trimmed.is_empty() {
            continue;
        }
        if Language::English.find_word(trimmed).is_none() {
            return Ok(Some(trimmed.to_string()));
        }
    }
    Ok(None)
}

#[tauri::command]
pub fn create_did(
    app_handle: AppHandle,
    nickname: String,
    password: String,
    mnemonic_words: Vec<String>,
) -> CommandResult<DidInfo> {
    let mnemonic_phrase = mnemonic_words.join(" ");
    let mnemonic = Mnemonic::parse_in(Language::English, &mnemonic_phrase)?;

    let requests = DidDerivationPlan::default_requests();
    let wallets = derive_wallets_with_requests(&mnemonic, "", &requests, None)?;

    let encrypted_seed = encrypt_mnemonic(&password, &mnemonic)?;

    let store = open_store(&app_handle)?;
    let mut vault = load_vault(&store)?;

    if vault
        .dids
        .iter()
        .any(|did| did.nickname.eq_ignore_ascii_case(&nickname))
    {
        return Err(CommandErrors::NicknameExists);
    }

    let record = StoredDid {
        id: new_did_id(),
        nickname,
        seed: encrypted_seed,
        wallets,
        sn_status: None,
    };

    vault.active_did = Some(record.id.clone());
    vault.dids.push(record.clone());

    save_vault(&store, &vault)?;

    Ok(record.to_info())
}

#[tauri::command]
pub fn import_did(
    app_handle: AppHandle,
    nickname: String,
    password: String,
    mnemonic_words: Vec<String>,
) -> CommandResult<DidInfo> {
    if mnemonic_words.is_empty() {
        return Err(CommandErrors::MnemonicRequired);
    }

    let decrypted = mnemonic_words.join(" ");
    let secret_phrase = SecretString::new(decrypted);
    let mnemonic = Mnemonic::parse_in(Language::English, secret_phrase.expose_secret())?;
    drop(secret_phrase);

    let requests = DidDerivationPlan::default_requests();
    let wallets = derive_wallets_with_requests(&mnemonic, "", &requests, None)?;

    let encrypted_seed = encrypt_mnemonic(&password, &mnemonic)?;

    let store = open_store(&app_handle)?;
    let mut vault = load_vault(&store)?;

    if vault
        .dids
        .iter()
        .any(|did| did.nickname.eq_ignore_ascii_case(&nickname))
    {
        return Err(CommandErrors::NicknameExists);
    }

    if let Some(new_identity) = wallets.bucky.entries.first() {
        if vault.dids.iter().any(|existing| {
            existing
                .wallets
                .bucky
                .entries
                .iter()
                .any(|entry| entry.did == new_identity.did)
        }) {
            return Err(CommandErrors::IdentityExists);
        }
    }

    let record = StoredDid {
        id: new_did_id(),
        nickname,
        seed: encrypted_seed,
        wallets,
        sn_status: None,
    };

    vault.active_did = Some(record.id.clone());
    vault.dids.push(record.clone());

    save_vault(&store, &vault)?;

    Ok(record.to_info())
}

#[tauri::command]
pub fn extend_wallets(
    app_handle: AppHandle,
    password: String,
    did_id: String,
    request: WalletExtensionKind,
) -> CommandResult<DidInfo> {
    let count = match &request {
        WalletExtensionKind::Btc { count, .. }
        | WalletExtensionKind::Eth { count }
        | WalletExtensionKind::Bucky { count } => *count,
    };
    if count == 0 {
        return Err(CommandErrors::CountMustBePositive);
    }

    let store = open_store(&app_handle)?;
    let mut vault = load_vault(&store)?;

    let info = {
        let record = vault
            .dids
            .iter_mut()
            .find(|did| did.id == did_id)
            .ok_or_else(|| CommandErrors::not_found("wallet_not_found"))?;

        let decrypted = decrypt_mnemonic(&password, &record.seed)?;
        let secret_phrase = SecretString::new(decrypted);
        let mnemonic = Mnemonic::parse_in(Language::English, secret_phrase.expose_secret())?;
        drop(secret_phrase);

        let requests = match request {
            WalletExtensionKind::Btc {
                address_type,
                count,
            } => vec![WalletRequest::btc(address_type, count)],
            WalletExtensionKind::Eth { count } => vec![WalletRequest::eth(count)],
            WalletExtensionKind::Bucky { count } => vec![WalletRequest::bucky(count)],
        };

        if requests.is_empty() {
            record.to_info()
        } else {
            let new_wallets =
                derive_wallets_with_requests(&mnemonic, "", &requests, Some(&record.wallets))?;
            record.wallets.merge(new_wallets);
            record.to_info()
        }
    };

    save_vault(&store, &vault)?;
    Ok(info)
}

#[tauri::command]
pub fn wallet_exists(app_handle: AppHandle) -> CommandResult<bool> {
    let store = open_store(&app_handle)?;
    let vault = load_vault(&store)?;
    Ok(!vault.dids.is_empty())
}

#[tauri::command]
pub fn list_dids(app_handle: AppHandle) -> CommandResult<Vec<DidInfo>> {
    let store = open_store(&app_handle)?;
    let vault = load_vault(&store)?;
    Ok(vault.dids.iter().map(StoredDid::to_info).collect())
}

#[tauri::command]
pub fn active_did(app_handle: AppHandle) -> CommandResult<Option<DidInfo>> {
    let store = open_store(&app_handle)?;
    let vault = load_vault(&store)?;

    Ok(vault.active_did.and_then(|id| {
        vault
            .dids
            .iter()
            .find(|did| did.id == id)
            .map(StoredDid::to_info)
    }))
}

#[tauri::command]
pub fn set_active_did(app_handle: AppHandle, did_id: String) -> CommandResult<DidInfo> {
    let store = open_store(&app_handle)?;
    let mut vault = load_vault(&store)?;

    let record = vault
        .dids
        .iter()
        .find(|did| did.id == did_id)
        .cloned()
        .ok_or_else(|| CommandErrors::not_found("wallet_not_found"))?;

    vault.active_did = Some(record.id.clone());
    save_vault(&store, &vault)?;

    Ok(record.to_info())
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Default)]
pub struct SnStatusPayload {
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone_config: Option<String>,
}

#[tauri::command]
pub fn list_sn_statuses(app_handle: AppHandle) -> CommandResult<HashMap<String, SnStatusInfo>> {
    let store = open_store(&app_handle)?;
    let vault = load_vault(&store)?;
    let mut map = HashMap::new();
    for did in &vault.dids {
        if let Some(status) = &did.sn_status {
            map.insert(did.id.clone(), status.clone());
        }
    }
    Ok(map)
}

#[tauri::command]
pub fn set_sn_status(
    app_handle: AppHandle,
    did_id: String,
    status: SnStatusPayload,
) -> CommandResult<()> {
    let store = open_store(&app_handle)?;
    let mut vault = load_vault(&store)?;

    let username = status
        .username
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let record = vault
        .dids
        .iter_mut()
        .find(|did| did.id == did_id)
        .ok_or_else(|| CommandErrors::not_found("wallet_not_found"))?;

    record.sn_status = Some(SnStatusInfo {
        username,
        zone_config: status
            .zone_config
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
    });

    save_vault(&store, &vault)
}

#[tauri::command]
pub fn clear_sn_status(app_handle: AppHandle, did_id: String) -> CommandResult<()> {
    let store = open_store(&app_handle)?;
    let mut vault = load_vault(&store)?;
    if let Some(record) = vault.dids.iter_mut().find(|did| did.id == did_id) {
        record.sn_status = None;
    }
    save_vault(&store, &vault)
}

#[tauri::command]
pub fn delete_wallet(
    app_handle: AppHandle,
    password: String,
    did_id: Option<String>,
) -> CommandResult<()> {
    let store = open_store(&app_handle)?;
    let mut vault = load_vault(&store)?;

    let target_id = match did_id {
        Some(id) => id,
        None => vault
            .active_did
            .clone()
            .ok_or_else(|| CommandErrors::not_found("wallet_not_found"))?,
    };

    let position = vault
        .dids
        .iter()
        .position(|did| did.id == target_id)
        .ok_or_else(|| CommandErrors::not_found("wallet_not_found"))?;

    let record = vault.dids.get(position).expect("did exists");
    decrypt_mnemonic(&password, &record.seed)?;

    vault.dids.remove(position);

    if matches!(vault.active_did.as_deref(), Some(active) if active == target_id) {
        vault.active_did = None;
    }

    save_vault(&store, &vault)?;
    Ok(())
}

#[tauri::command]
pub fn reveal_mnemonic(
    app_handle: AppHandle,
    password: String,
    did_id: Option<String>,
) -> CommandResult<Vec<String>> {
    let store = open_store(&app_handle)?;
    let vault = load_vault(&store)?;

    let target_id = did_id
        .or_else(|| vault.active_did.clone())
        .ok_or_else(|| CommandErrors::not_found("wallet_not_found"))?;

    let record = vault
        .dids
        .iter()
        .find(|did| did.id == target_id)
        .ok_or_else(|| CommandErrors::not_found("wallet_not_found"))?;

    let decrypted = decrypt_mnemonic(&password, &record.seed)?;
    let secret_phrase = SecretString::new(decrypted);
    let mnemonic = Mnemonic::parse_in(Language::English, secret_phrase.expose_secret())?;
    drop(secret_phrase);

    Ok(mnemonic
        .to_string()
        .split_whitespace()
        .map(|w| w.to_string())
        .collect())
}

#[tauri::command]
pub fn current_wallet_nickname(app_handle: AppHandle) -> CommandResult<Option<String>> {
    let store = open_store(&app_handle)?;
    let vault = load_vault(&store)?;

    match &vault.active_did {
        Some(active_id) => Ok(vault
            .dids
            .iter()
            .find(|did| &did.id == active_id)
            .map(|did| did.nickname.clone())),
        None => Ok(None),
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ZoneBootClaims {
    oods: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sn: Option<String>,
    exp: usize,
    iat: usize,
}

fn load_active_signing_key(
    app_handle: &AppHandle,
    password: &str,
) -> CommandResult<(EncodingKey, Option<String>)> {
    let store = open_store(app_handle)?;
    let vault = load_vault(&store)?;
    let target_id = vault
        .active_did
        .clone()
        .ok_or_else(|| CommandErrors::not_found("wallet_not_found"))?;

    let record = vault
        .dids
        .iter()
        .find(|d| d.id == target_id)
        .ok_or_else(|| CommandErrors::not_found("wallet_not_found"))?;

    let decrypted = decrypt_mnemonic(password, &record.seed)?;
    let secret_phrase = SecretString::new(decrypted);
    let mnemonic = Mnemonic::parse_in(Language::English, secret_phrase.expose_secret())?;
    drop(secret_phrase);

    let phrase = mnemonic.to_string();
    let passphrase_opt: Option<&str> = None;
    let index = 0u32;
    let (private_pem, _public_jwk) =
        name_lib::generate_ed25519_key_pair_from_mnemonic(&phrase, passphrase_opt, index)
            .map_err(|e| CommandErrors::crypto_failed(e.to_string()))?;

    let pem_key = EncodingKey::from_ed_pem(private_pem.as_bytes())
        .map_err(|e| CommandErrors::crypto_failed(format!("invalid ed25519 private key: {e}")))?;

    let did_label = record
        .wallets
        .bucky
        .entries
        .first()
        .map(|entry| entry.did.clone());

    Ok((pem_key, did_label))
}

#[tauri::command]
pub fn sign_json_with_active_did(
    app_handle: AppHandle,
    password: String,
    payloads: Vec<Value>,
) -> CommandResult<Vec<Option<String>>> {
    let mut sanitized = Vec::with_capacity(payloads.len());
    let mut invalid_found = false;
    for value in payloads {
        match value {
            Value::Object(_) => sanitized.push(value),
            _ => {
                invalid_found = true;
                break;
            }
        }
    }

    if sanitized.is_empty() || invalid_found {
        return Err(CommandErrors::SignMessageRequired);
    }

    let (pem_key, _did_label) = load_active_signing_key(&app_handle, &password)?;

    let mut signatures = Vec::with_capacity(sanitized.len());
    for payload in sanitized {
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = None;
        header.typ = None;

        match encode(&header, &payload, &pem_key) {
            Ok(token) => signatures.push(Some(token)),
            Err(err) => {
                log::error!("sign_json_with_active_did encode failed: {err}");
                signatures.push(None);
            }
        }
    }

    Ok(signatures)
}

#[tauri::command]
pub fn generate_zone_boot_config_jwt(
    app_handle: AppHandle,
    password: String,
    did_id: Option<String>,
    sn: Option<String>,
    #[allow(unused_variables)] ood_name: Option<String>,
) -> CommandResult<String> {
    // resolve target DID (active by default)
    let store = open_store(&app_handle)?;
    let vault = load_vault(&store)?;
    let target_id = did_id
        .or(vault.active_did.clone())
        .ok_or_else(|| CommandErrors::not_found("wallet_not_found"))?;
    let record = vault
        .dids
        .iter()
        .find(|d| d.id == target_id)
        .ok_or_else(|| CommandErrors::not_found("wallet_not_found"))?;

    // unlock mnemonic to validate password and derive private key
    let decrypted = decrypt_mnemonic(&password, &record.seed)?;
    let secret_phrase = SecretString::new(decrypted);
    let mnemonic = Mnemonic::parse_in(Language::English, secret_phrase.expose_secret())?;
    drop(secret_phrase);

    // derive ed25519 owner private key from mnemonic index 0 (Bucky identity)
    let phrase = mnemonic.to_string();
    let passphrase_opt: Option<&str> = None;
    let index = 0u32;
    let (private_pem, _public_jwk) =
        name_lib::generate_ed25519_key_pair_from_mnemonic(&phrase, passphrase_opt, index)
            .map_err(|e| CommandErrors::crypto_failed(e.to_string()))?;

    let pem_key = EncodingKey::from_ed_pem(private_pem.as_bytes())
        .map_err(|e| CommandErrors::crypto_failed(format!("invalid ed25519 private key: {e}")))?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| CommandErrors::internal(e.to_string()))?
        .as_secs() as usize;

    let ood = ood_name.unwrap_or_else(|| "ood1".to_string());
    let claims = ZoneBootClaims {
        oods: vec![ood],
        sn: sn.filter(|s| !s.is_empty()),
        // 10 years validity
        exp: now + 3600 * 24 * 365 * 10,
        iat: now,
    };

    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = None;
    header.typ = None;
    let token = encode(&header, &claims, &pem_key)?;

    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::domain::DEFAULT_BTC_ADDRESS_TYPE;
    use super::*;
    use tauri::test::mock_app;

    #[test]
    fn test_generate_mnemonic() {
        let words = generate_mnemonic().unwrap();
        assert_eq!(words.len(), 12);
    }

    #[test]
    fn test_eth_address_derivation_and_eip55() {
        let mnemonic = Mnemonic::parse_in(
            Language::English,
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap();
        let ctx = SeedCtx::new(&mnemonic, "").unwrap();
        let address = derive_eth_address(&ctx, 0).unwrap();
        assert_eq!(address, "0x9858EfFD232B4033E47d90003D41EC34EcaEda94");
    }

    #[test]
    fn test_create_did_flow() {
        let app = mock_app()
            .plugin(tauri_plugin_store::Builder::default().build())
            .build();
        let app_handle = app.handle();

        let nickname = "test_user".to_string();
        let password = "password123".to_string();
        let mnemonic_words = vec![
            "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
            "abandon", "abandon", "abandon", "about",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        let did_info = create_did(
            app_handle.clone(),
            nickname.clone(),
            password.clone(),
            mnemonic_words,
        )
        .unwrap();

        assert_eq!(did_info.nickname, nickname);
        assert!(did_info.btc_addresses.is_empty());
        assert!(did_info.eth_addresses.is_empty());
        assert_eq!(did_info.bucky_wallets.len(), 1);
        let identity = &did_info.bucky_wallets[0];
        assert_eq!(identity.index, 0);
        assert!(
            identity.did.starts_with("did:dev:"),
            "unexpected DID: {}",
            identity.did
        );

        let dids = list_dids(app_handle.clone()).unwrap();
        assert_eq!(dids.len(), 1);
        assert_eq!(dids[0].id, did_info.id);
        assert_eq!(dids[0].bucky_wallets.len(), 1);

        let active = active_did(app_handle.clone()).unwrap().unwrap();
        assert_eq!(active.id, did_info.id);

        let mnemonic = reveal_mnemonic(
            app_handle.clone(),
            password.clone(),
            Some(did_info.id.clone()),
        )
        .unwrap();
        assert_eq!(mnemonic.len(), 12);

        delete_wallet(app_handle.clone(), password, Some(did_info.id)).unwrap();
        let dids_after = list_dids(app_handle).unwrap();
        assert!(dids_after.is_empty());
    }

    #[test]
    fn test_extend_wallets() {
        let app = mock_app()
            .plugin(tauri_plugin_store::Builder::default().build())
            .build();
        let app_handle = app.handle();

        let nickname = "extend_user".to_string();
        let password = "password123".to_string();
        let mnemonic_words = vec![
            "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
            "abandon", "abandon", "abandon", "about",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        let did_info = create_did(
            app_handle.clone(),
            nickname.clone(),
            password.clone(),
            mnemonic_words,
        )
        .unwrap();

        let extended_btc = extend_wallets(
            app_handle.clone(),
            password.clone(),
            did_info.id.clone(),
            WalletExtensionKind::Btc {
                address_type: DEFAULT_BTC_ADDRESS_TYPE,
                count: 2,
            },
        )
        .unwrap();
        assert_eq!(extended_btc.btc_addresses.len(), 2);

        let extended_eth = extend_wallets(
            app_handle.clone(),
            password.clone(),
            did_info.id.clone(),
            WalletExtensionKind::Eth { count: 1 },
        )
        .unwrap();
        assert_eq!(extended_eth.eth_addresses.len(), 1);

        let extended_bucky = extend_wallets(
            app_handle.clone(),
            password.clone(),
            did_info.id.clone(),
            WalletExtensionKind::Bucky { count: 1 },
        )
        .unwrap();
        assert_eq!(extended_bucky.bucky_wallets.len(), 2);

        let listed = list_dids(app_handle.clone()).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].btc_addresses.len(), 2);
        assert_eq!(listed[0].eth_addresses.len(), 1);
        assert_eq!(listed[0].bucky_wallets.len(), 2);

        delete_wallet(app_handle.clone(), password, Some(did_info.id)).unwrap();
        let after_delete = list_dids(app_handle).unwrap();
        assert!(after_delete.is_empty());
    }
}
