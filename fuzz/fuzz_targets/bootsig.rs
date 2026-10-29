// SPDX-License-Identifier: Apache-2.0
//! Coverage-guided fuzzing of `boot.sig` and its signature check.
//!
//! RFC 0091: `bhaskix\boot.sig` is read off an EFI system partition anybody
//! with the disk can write, and the loader parses it before it decides
//! whether to boot. It is hostile input by definition, so `docs/coding-style.md`
//! §8 applies before it merges.
//!
//! # Three arms, one per input
//!
//! The first byte picks the arm. One verification is thousands of SHA-256
//! compressions, and running it on every input would hold the cheap arms to
//! its pace.
//!
//! **Arm A, raw bytes.** `BootSig::parse` and `check` over whatever arrived.
//! This is the baseline, and the arm that proves the refusal paths do not
//! panic.
//!
//! **Arm B, the statement's shape with the fuzzer's values.** A 7,984-byte file
//! with the magic in place. Each field is chosen by the fuzzer to be right
//! (the one algorithm, version 0, the held key's id, the held digests) or its
//! own bytes, and the signature is always the fuzzer's. This is the arm that
//! gets past the parse to every comparison and into the verifier. Its oracle
//! is the property the whole design rests on: **no input it can build is
//! accepted**, because none carries a signature somebody made.
//!
//! **Arm C, a real signature, bent.** A valid NIST vector (public key,
//! context, message, signature) with fuzzer-chosen bytes flipped across all
//! four. The oracle is exact. Unchanged, it verifies; changed anywhere, it
//! must not. A context pushed past 255 bytes must be refused as too long.

#![no_main]

use bhaskix_bootsig::slh_dsa::{self, PUBLIC_KEY_BYTES};
use bhaskix_bootsig::statement::{self, ALGORITHM, BOOT_SIG_BYTES, BootSig, Digests, MAGIC};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fuzz_target!(|data: &[u8]| {
    run(data);
});

/// Dispatches on the first byte, so a host harness can drive the arms too.
fn run(data: &[u8]) {
    let Some((&which, rest)) = data.split_first() else {
        return;
    };
    match which % 3 {
        0 => arm_a(rest),
        1 => arm_b(rest),
        _ => arm_c(rest),
    }
}

/// The key and the digests the loader holds in arms A and B.
const KEY: [u8; PUBLIC_KEY_BYTES] = [0x5a; PUBLIC_KEY_BYTES];

fn held() -> Digests {
    Digests {
        kernel: [1; 32],
        initrd: [2; 32],
        boot_conf: [3; 32],
    }
}

/// A cursor over the fuzzer's bytes that never fails: past the end, every
/// read is zero.
struct Input<'a> {
    bytes: &'a [u8],
}

impl Input<'_> {
    fn byte(&mut self) -> u8 {
        match self.bytes.split_first() {
            Some((&first, rest)) => {
                self.bytes = rest;
                first
            }
            None => 0,
        }
    }

    fn word(&mut self) -> u32 {
        u32::from_le_bytes([self.byte(), self.byte(), self.byte(), self.byte()])
    }

    fn fill(&mut self, out: &mut [u8]) {
        for slot in out {
            *slot = self.byte();
        }
    }
}

fn arm_a(data: &[u8]) {
    if let Ok(sig) = BootSig::parse(data) {
        let _ = sig.key_id();
    }
    let _ = statement::check(data, &[KEY], &held());
}

fn arm_b(data: &[u8]) {
    let mut input = Input { bytes: data };
    let choices = input.byte();
    let held = held();
    let mut file = vec![0u8; BOOT_SIG_BYTES];
    file[..16].copy_from_slice(&MAGIC);
    let algorithm = if choices & 1 == 0 {
        ALGORITHM
    } else {
        input.word()
    };
    let version = if choices & 2 == 0 { 0 } else { input.word() };
    file[16..20].copy_from_slice(&algorithm.to_le_bytes());
    file[20..24].copy_from_slice(&version.to_le_bytes());
    if choices & 4 == 0 {
        file[24..32].copy_from_slice(&statement::key_id(&KEY));
    } else {
        input.fill(&mut file[24..32]);
    }
    for (bit, at, digest) in [
        (8, 32, held.kernel),
        (16, 64, held.initrd),
        (32, 96, held.boot_conf),
    ] {
        if choices & bit == 0 {
            file[at..at + 32].copy_from_slice(&digest);
        } else {
            input.fill(&mut file[at..at + 32]);
        }
    }
    input.fill(&mut file[128..]);
    assert!(
        statement::check(&file, &[KEY], &held).is_err(),
        "a boot.sig nobody signed was accepted"
    );
}

/// One valid vector from the external, pure group, read once.
struct Vector {
    pk: [u8; PUBLIC_KEY_BYTES],
    context: Vec<u8>,
    message: Vec<u8>,
    signature: Vec<u8>,
}

fn vector() -> &'static Vector {
    static VECTOR: OnceLock<Vector> = OnceLock::new();
    VECTOR.get_or_init(|| {
        let text = include_str!("../../third_party/acvp-slh-dsa/sha2-128s-sigver.tsv");
        let line = text
            .lines()
            .find(|line| {
                let fields: Vec<&str> = line.split('\t').collect();
                fields.len() == 8 && fields[1] == "19" && fields[2] == "true"
            })
            .unwrap_or_default();
        let fields: Vec<&str> = line.split('\t').collect();
        let unhex = |text: &str| -> Vec<u8> {
            (0..text.len() / 2)
                .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap_or(0))
                .collect()
        };
        let mut pk = [0; PUBLIC_KEY_BYTES];
        pk.copy_from_slice(&unhex(fields[4]));
        Vector {
            pk,
            context: unhex(fields[5]),
            message: unhex(fields[6]),
            signature: unhex(fields[7]),
        }
    })
}

fn arm_c(data: &[u8]) {
    let original = vector();
    let mut pk = original.pk;
    let mut context = original.context.clone();
    let mut message = original.message.clone();
    let mut signature = original.signature.clone();
    let mut input = Input { bytes: data };
    let flips = input.byte() % 8;
    for _ in 0..flips {
        let target = input.byte();
        let at = usize::from(input.byte()) << 8 | usize::from(input.byte());
        let xor = input.byte();
        let field: &mut [u8] = match target % 4 {
            0 => &mut pk,
            1 => &mut context,
            2 => &mut message,
            _ => &mut signature,
        };
        if !field.is_empty() {
            let len = field.len();
            field[at % len] ^= xor;
        }
    }
    // Lengthen the context past 255 now and then, which must be refused as such.
    if input.byte() == 0xff {
        context.resize(256, 0);
    }
    let unchanged = pk == original.pk
        && context == original.context
        && message == original.message
        && signature == original.signature;
    let verdict = slh_dsa::verify(&message, &signature, &context, &pk);
    if context.len() > 255 {
        assert_eq!(verdict, Err(slh_dsa::Refusal::ContextTooLong));
    } else if unchanged {
        assert_eq!(verdict, Ok(()), "a NIST-valid signature was refused");
    } else {
        assert!(verdict.is_err(), "a bent signature was accepted");
    }
}
