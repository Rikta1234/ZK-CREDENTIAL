use clap::{Parser, Subcommand};
use issuer_rust::crypto;
use issuer_rust::format::{AttributeData, Credential, Session, SessionPublic};
use std::collections::HashMap;
use std::fs;
use std::time::Instant;

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(name = "issuer", author, version, about = "CRCS Phase I — Issuer Node")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Issue a new credential for a holder's attributes
    Issue {
        /// Holder's age (integer)
        #[arg(long)]
        age: u64,

        /// Holder's annual income (integer)
        #[arg(long)]
        income: u64,

        /// Output path for the credential JSON
        #[arg(short, long, default_value = "credential.json")]
        out: String,

        /// Print timing and size metrics after issuing
        #[arg(long)]
        print_metrics: bool,
    },

    /// Create a fresh proof session for a given verifier
    Session {
        /// Path to an existing credential JSON
        #[arg(long)]
        cred: String,

        /// Verifier identifier string (e.g. "BANK_A" or "INSURANCE_B")
        #[arg(long)]
        verifier: String,

        /// Min age threshold to embed in session
        #[arg(long, default_value = "18")]
        min_age: u64,

        /// Min income threshold to embed in session
        #[arg(long, default_value = "500000")]
        min_income: u64,

        /// Output path for the session JSON
        #[arg(short, long, default_value = "session.json")]
        out: String,

        /// Print timing metrics
        #[arg(long)]
        print_metrics: bool,
    },
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Issue {
            age,
            income,
            out,
            print_metrics,
        } => cmd_issue(age, income, &out, print_metrics),

        Commands::Session {
            cred,
            verifier,
            min_age,
            min_income,
            out,
            print_metrics,
        } => cmd_session(&cred, &verifier, min_age, min_income, &out, print_metrics),
    }
}

// ---------------------------------------------------------------------------
// `issuer issue`
// ---------------------------------------------------------------------------

fn cmd_issue(age: u64, income: u64, out_path: &str, metrics: bool) {
    let t_start = Instant::now();

    // --- Convert to field elements ---
    let age_fr = crypto::u64_to_fr(age);
    let income_fr = crypto::u64_to_fr(income);

    // --- Generate shares: x1 ←$ Fr, x2 = x - x1 ---
    let (age_x1, age_x2) = crypto::generate_shares(&age_fr);
    let (inc_x1, inc_x2) = crypto::generate_shares(&income_fr);

    // --- Sample blinding randomness ---
    let age_r = crypto::random_fr();
    let inc_r = crypto::random_fr();

    // --- Compute base commitments C = Poseidon(x, r) ---
    let age_c = crypto::compute_base_commitment(&age_fr, &age_r);
    let inc_c = crypto::compute_base_commitment(&income_fr, &inc_r);

    // --- Issuer keypair + signature ---
    let (sk, vk) = crypto::generate_keypair();
    let cred_id = uuid::Uuid::new_v4().to_string();
    let msg = crypto::credential_message(&cred_id, &[&age_c, &inc_c]);
    let sig = crypto::sign_message(&sk, &msg);
    let pk_hex = crypto::pk_to_hex(&vk);

    // --- Assemble credential ---
    let mut attributes = HashMap::new();
    attributes.insert(
        "age".to_string(),
        AttributeData {
            x1: crypto::fr_to_decimal(&age_x1),
            x2: crypto::fr_to_decimal(&age_x2),
            r:  crypto::fr_to_decimal(&age_r),
            c:  crypto::fr_to_decimal(&age_c),
        },
    );
    attributes.insert(
        "income".to_string(),
        AttributeData {
            x1: crypto::fr_to_decimal(&inc_x1),
            x2: crypto::fr_to_decimal(&inc_x2),
            r:  crypto::fr_to_decimal(&inc_r),
            c:  crypto::fr_to_decimal(&inc_c),
        },
    );

    let credential = Credential {
        credential_id: cred_id,
        issuer_pk: pk_hex,
        sig,
        attributes,
    };

    // --- Write JSON ---
    let json = serde_json::to_string_pretty(&credential).expect("serialisation failed");
    fs::write(out_path, &json).expect("failed to write credential.json");

    let elapsed = t_start.elapsed();
    println!("✅  Credential issued → {out_path}");

    if metrics {
        println!("--- Metrics ---");
        println!("  Issue time  : {:.2?}", elapsed);
        println!("  File size   : {} bytes", json.len());
    }
}

// ---------------------------------------------------------------------------
// `issuer session`
// ---------------------------------------------------------------------------

fn cmd_session(
    cred_path: &str,
    verifier_id: &str,
    min_age: u64,
    min_income: u64,
    out_path: &str,
    metrics: bool,
) {
    let t_start = Instant::now();

    // --- Load credential ---
    let raw = fs::read_to_string(cred_path).expect("cannot read credential file");
    let cred: Credential = serde_json::from_str(&raw).expect("invalid credential JSON");

    // --- Fresh nonce ←$ Fr  (one per session — guarantees unlinkability) ---
    let nonce = crypto::random_fr();

    // --- Verifier domain tag = Poseidon-friendly encoding of verifier_id string ---
    let domain = crypto::bytes_to_fr(verifier_id.as_bytes());

    // --- Compute per-attribute session commitments ---
    let mut public = HashMap::new();
    for (attr_name, attr_data) in &cred.attributes {
        let c = crypto::decimal_to_fr(&attr_data.c);
        let sc = crypto::compute_session_commitment(&c, &nonce, &domain);
        public.insert(
            attr_name.clone(),
            SessionPublic {
                sc: crypto::fr_to_decimal(&sc),
            },
        );
    }

    // --- Embed thresholds ---
    let mut thresholds = HashMap::new();
    thresholds.insert("age_min".to_string(), min_age);
    thresholds.insert("income_min".to_string(), min_income);

    let session = Session {
        verifier_id: verifier_id.to_string(),
        nonce: crypto::fr_to_decimal(&nonce),
        thresholds,
        public,
    };

    // --- Write JSON ---
    let json = serde_json::to_string_pretty(&session).expect("serialisation failed");
    fs::write(out_path, &json).expect("failed to write session.json");

    let elapsed = t_start.elapsed();
    println!("✅  Session created  → {out_path}  (verifier: {verifier_id})");

    if metrics {
        println!("--- Metrics ---");
        println!("  Session time : {:.2?}", elapsed);
        println!("  File size    : {} bytes", json.len());
    }
}
