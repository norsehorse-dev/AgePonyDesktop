//! Generate a post-quantum interop fixture.
//!
//! Produces an identity file and a file encrypted to its recipient, so the
//! result can be carried to AgePony iOS or Android (or Go `age` v1.3.0+) and
//! opened there. That is the one leg of interop this repo cannot test in CI:
//! `rage` does not implement `mlkem768x25519`, so there is no reference CLI to
//! round-trip against.
//!
//! ```text
//! cargo run -p agepony-core --example make_pq_fixture -- <output-dir>
//! ```

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir: PathBuf = std::env::args()
        .nth(1)
        .unwrap_or_else(|| ".".to_owned())
        .into();
    std::fs::create_dir_all(&dir)?;

    let identity = agepony_core::identity::generate_pq()?;
    let recipient = identity.to_public()?;
    let recipient_str = recipient.to_string();

    let id_path = dir.join("pq_identity.txt");
    let body = agepony_core::identity::identity_file_body(&recipient_str, &identity.to_bech32()?);
    agepony_core::identity::save_identity_file(&id_path, &body)?;

    let plain_path = dir.join("pq_hello.txt");
    let ct_path = dir.join("pq_hello.age");
    std::fs::write(&plain_path, b"hello AgePony")?;

    let parsed = agepony_core::recipient::parse_all([recipient_str.as_str()])?;
    agepony_core::encrypt::encrypt_file(
        &plain_path,
        &ct_path,
        agepony_core::encrypt::To::Recipients(&parsed),
        false,
        &mut |_| true,
    )?;

    println!("identity:   {}", id_path.display());
    println!("ciphertext: {}", ct_path.display());
    println!("plaintext:  hello AgePony");
    println!("recipient:  {recipient_str}");
    Ok(())
}
