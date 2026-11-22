use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use std::env;
use std::process::{Command, ExitCode};

fn store_in_offline_vault(vault_cli: &str, key_name: &str, secret_val: &str, desc: &str) -> Result<(), String> {
    let output = Command::new(vault_cli)
        .args([
            "vault",
            "set",
            key_name,
            secret_val,
            "-c",
            "oniontalk",
            "--host",
            "org.oniontalk.messenger",
            "-d",
            desc,
        ])
        .output()
        .map_err(|e| format!("Failed to invoke vault CLI: {}", e))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("vault set failed for {}: {}", key_name, stderr.trim()));
    }
    Ok(())
}

fn fetch_from_offline_vault(vault_cli: &str, key_name: &str) -> Result<String, String> {
    let output = Command::new(vault_cli)
        .args(["vault", "get", key_name])
        .output()
        .map_err(|e| format!("Failed to invoke vault CLI get: {}", e))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("vault get failed for {}: {}", key_name, stderr.trim()));
    }
    let val = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if val.len() != 64 || !val.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("Unexpected seed format retrieved for {}", key_name));
    }
    Ok(val.to_ascii_lowercase())
}

fn zeroize_string(s: &mut String) {
    unsafe {
        for b in s.as_bytes_mut() {
            std::ptr::write_volatile(b, 0);
        }
    }
    s.clear();
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!(
            "Usage:\n  authority_tool provision-vault <vault_cli>\n  authority_tool sign-crl --vault-cli <exe> --vault-key <key> --epoch <sec> --revoked <csv> --delegated <csv>"
        );
        return ExitCode::from(2);
    }

    match args[1].as_str() {
        "provision-vault" => {
            let Some(vault_cli) = args.get(2) else {
                eprintln!("Missing <vault_cli> path");
                return ExitCode::from(2);
            };
            for idx in 1..=2 {
                let signing_key = SigningKey::generate(&mut OsRng);
                let mut seed_bytes = signing_key.to_bytes();
                let mut seed_hex = hex::encode(seed_bytes);
                for b in &mut seed_bytes {
                    unsafe { std::ptr::write_volatile(b, 0) };
                }
                let pub_hex = hex::encode(signing_key.verifying_key().to_bytes());
                let seed_key = format!("oniontalk_offline_root_ca_{}_seed_hex", idx);
                let pub_key = format!("oniontalk_offline_root_ca_{}_pubkey_hex", idx);

                let res_seed = store_in_offline_vault(
                    vault_cli,
                    &seed_key,
                    &seed_hex,
                    &format!("Air-Gapped Offline Root CA #{} Ed25519 Private Seed (otcrl1: authority)", idx),
                );
                zeroize_string(&mut seed_hex);
                if let Err(err) = res_seed {
                    eprintln!("ERROR: {}", err);
                    return ExitCode::from(1);
                }
                if let Err(err) = store_in_offline_vault(
                    vault_cli,
                    &pub_key,
                    &pub_hex,
                    &format!("Air-Gapped Offline Root CA #{} Ed25519 Public Key", idx),
                ) {
                    eprintln!("ERROR: {}", err);
                    return ExitCode::from(1);
                }
                println!("ROOT_CA_{}_PUBKEY={}", idx, pub_hex);
            }
            ExitCode::SUCCESS
        }
        "sign-crl" => {
            let mut vault_cli = String::new();
            let mut vault_key = "oniontalk_offline_root_ca_1_seed_hex".to_string();
            let mut epoch_sec: u64 = 0;
            let mut revoked_csv = String::new();
            let mut delegated_csv = String::new();

            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--vault-cli" => {
                        i += 1;
                        vault_cli = args.get(i).cloned().unwrap_or_default();
                    }
                    "--vault-key" => {
                        i += 1;
                        vault_key = args.get(i).cloned().unwrap_or_default();
                    }
                    "--epoch" => {
                        i += 1;
                        epoch_sec = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(0);
                    }
                    "--revoked" => {
                        i += 1;
                        revoked_csv = args.get(i).cloned().unwrap_or_default();
                    }
                    "--delegated" => {
                        i += 1;
                        delegated_csv = args.get(i).cloned().unwrap_or_default();
                    }
                    _ => {}
                }
                i += 1;
            }
            if epoch_sec == 0 {
                eprintln!("--epoch <sec> must be > 0");
                return ExitCode::from(2);
            }

            let mut seed_hex = if let Ok(env_seed) = env::var("OFFLINE_ROOT_CA_SEED_HEX") {
                env_seed.trim().to_ascii_lowercase()
            } else if !vault_cli.is_empty() {
                match fetch_from_offline_vault(&vault_cli, &vault_key) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("ERROR: {}", e);
                        return ExitCode::from(1);
                    }
                }
            } else {
                eprintln!("Provide --vault-cli <exe> or OFFLINE_ROOT_CA_SEED_HEX");
                return ExitCode::from(2);
            };

            let Ok(mut seed_vec) = hex::decode(&seed_hex) else {
                zeroize_string(&mut seed_hex);
                eprintln!("Invalid hex seed");
                return ExitCode::from(1);
            };
            zeroize_string(&mut seed_hex);
            let Ok(mut seed_arr) = <[u8; 32]>::try_from(seed_vec.as_slice()) else {
                for b in &mut seed_vec {
                    unsafe { std::ptr::write_volatile(b, 0) };
                }
                eprintln!("Seed must be 32 bytes");
                return ExitCode::from(1);
            };
            for b in &mut seed_vec {
                unsafe { std::ptr::write_volatile(b, 0) };
            }

            let signing_key = SigningKey::from_bytes(&seed_arr);
            for b in &mut seed_arr {
                unsafe { std::ptr::write_volatile(b, 0) };
            }
            let root_pub_hex = hex::encode(signing_key.verifying_key().to_bytes());
            let clean_revoked = revoked_csv.trim().to_ascii_lowercase();
            let clean_delegated = delegated_csv.trim().to_ascii_lowercase();
            let canonical = format!(
                "ONIONTALK_AUTHORITY_CRL_V1|{}|{}|{}|{}",
                epoch_sec, clean_revoked, clean_delegated, root_pub_hex
            );
            let sig_hex = hex::encode(signing_key.sign(canonical.as_bytes()).to_bytes());
            println!(
                "otcrl1:{}:{}:{}:{}:{}",
                epoch_sec, clean_revoked, clean_delegated, root_pub_hex, sig_hex
            );
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("Unknown subcommand: {}", args[1]);
            ExitCode::from(2)
        }
    }
}
