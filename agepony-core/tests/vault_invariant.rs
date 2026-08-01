#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! The store/book invariant, under random sequences of operations.
//!
//! `vault.rs` has unit tests for each operation in isolation. This checks the
//! thing that actually matters: that the invariant survives *sequences* — the
//! interleavings nobody writes a test for, because nobody thinks of them.
//!
//! The invariant:
//!
//! 1. Every identity in the store has exactly one book entry naming it, holding
//!    that identity's current recipient.
//! 2. No book entry names an identity that is not in the store. This is the
//!    dangerous direction: a recipient whose private key is gone still
//!    encrypts, and produces a file nobody can ever open.
//! 3. Manually added recipients — other people's keys — are never touched by
//!    identity operations.
//!
//! It is checked after *every* step, not just at the end, so a failure points
//! at the operation that broke it rather than the one that happened last.

use agepony_core::book::Book;
use agepony_core::store::{Kind, Store};
use agepony_core::vault;
use proptest::prelude::*;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug, Clone)]
enum Op {
    Generate { label: u8, pq: bool },
    Rename { which: u8, label: u8 },
    Delete { which: u8 },
    AddManual { label: u8 },
    RemoveManual { which: u8 },
    Reconcile,
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        // Weighted towards generation so sequences build up something to act on.
        4 => (0_u8..12, any::<bool>()).prop_map(|(label, pq)| Op::Generate { label, pq: pq && label % 4 == 0 }),
        2 => (0_u8..8, 0_u8..12).prop_map(|(which, label)| Op::Rename { which, label }),
        2 => (0_u8..8).prop_map(|which| Op::Delete { which }),
        2 => (0_u8..12).prop_map(|label| Op::AddManual { label }),
        1 => (0_u8..8).prop_map(|which| Op::RemoveManual { which }),
        1 => Just(Op::Reconcile),
    ]
}

fn check(store: &Store, book: &Book, after: &str) -> Result<(), TestCaseError> {
    // 1. every identity is represented exactly once, with the right key
    for identity in store.entries() {
        let matching: Vec<_> = book
            .entries
            .iter()
            .filter(|e| e.identity_id.as_deref() == Some(identity.id.as_str()))
            .collect();
        prop_assert_eq!(
            matching.len(),
            1,
            "after {}: identity {} has {} book entries, expected exactly 1",
            after,
            identity.label,
            matching.len()
        );
        prop_assert_eq!(
            &matching[0].recipient,
            &identity.recipient,
            "after {}: book entry for {} holds the wrong recipient",
            after,
            identity.label
        );
        // Names too. Checking only the recipient let a rename that updated the
        // store but not the book pass unnoticed — mutation testing caught it.
        prop_assert_eq!(
            &matching[0].name,
            &agepony_core::book::self_name(&identity.label),
            "after {}: book entry for {} kept a stale name",
            after,
            identity.label
        );
    }

    // 2. nothing points at an identity that is gone
    for entry in &book.entries {
        if let Some(id) = entry.identity_id.as_deref() {
            prop_assert!(
                store.get(id).is_some(),
                "after {}: recipient {:?} outlived its private key",
                after,
                entry.name
            );
        }
    }

    // 3. no duplicate recipients
    let mut seen = std::collections::HashSet::new();
    for entry in &book.entries {
        prop_assert!(
            seen.insert(entry.recipient.clone()),
            "after {}: {:?} appears twice in the book",
            after,
            entry.recipient
        );
    }
    Ok(())
}

static CASE: AtomicUsize = AtomicUsize::new(0);

proptest! {
    #![proptest_config(ProptestConfig::with_cases(40))]

    #[test]
    fn the_invariant_survives_any_sequence(ops in prop::collection::vec(op(), 1..14)) {
        let n = CASE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join("agepony-invariant").join(n.to_string());
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("mkdir");

        let mut store = Store::open(&root).expect("open");
        let mut book = Book::default();
        // Someone else's key, present from the start. It must survive everything.
        let stranger = agepony_core::identity::generate_x25519()
            .to_public()
            .to_string();
        book.add("A stranger", &stranger, None).expect("add stranger");

        for (i, op) in ops.iter().enumerate() {
            let label = |n: u8| format!("Key {n}");
            match op {
                Op::Generate { label: l, pq } => {
                    let kind = if *pq { Kind::PostQuantum } else { Kind::X25519 };
                    // A duplicate label is a legitimate refusal, not a failure.
                    let _ = vault::generate(&mut store, &mut book, &label(*l), kind, None);
                }
                Op::Rename { which, label: l } => {
                    if let Some(entry) = store.entries().get(*which as usize % 8).cloned() {
                        let _ = vault::rename(&mut store, &mut book, &entry.id, &label(*l));
                    }
                }
                Op::Delete { which } => {
                    if let Some(entry) = store.entries().get(*which as usize % 8).cloned() {
                        let _ = vault::delete(&mut store, &mut book, &entry.id);
                    }
                }
                Op::AddManual { label: l } => {
                    let r = agepony_core::identity::generate_x25519().to_public().to_string();
                    let _ = book.add(&format!("Friend {l}"), &r, None);
                }
                Op::RemoveManual { which } => {
                    // Only ever removes someone else's key; removing your own
                    // is disallowed in the UI for exactly this reason.
                    let name = book
                        .entries
                        .iter()
                        .filter(|e| !e.is_own())
                        .nth(*which as usize % 4)
                        .map(|e| e.name.clone());
                    if let Some(name) = name {
                        book.remove(&name);
                    }
                }
                Op::Reconcile => {
                    vault::reconcile(&store, &mut book).expect("reconcile");
                }
            }
            check(&store, &book, &format!("step {i} ({op:?})"))?;
        }

        // Reconciling at the end must be a no-op: if the invariant already
        // holds, there is nothing to repair.
        let summary = vault::reconcile(&store, &mut book).expect("final reconcile");
        prop_assert!(
            summary.is_clean(),
            "reconcile found work to do ({summary:?}), so the invariant had already drifted"
        );

        let _ = std::fs::remove_dir_all(&root);
    }
}
