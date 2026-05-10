// ============================================================
// cracker.rs — Parallel crack loop
//
// This is the hot path — the code that runs millions of times.
//
// Architecture:
//   1. A reader thread streams wordlist lines through a channel
//      (see wordlist.rs)
//   2. The main crack loop reads from that channel
//   3. For each word, the rule engine generates mutations
//   4. Mutations are verified against the hash in parallel
//      using rayon's par_iter
//   5. The first match found is returned immediately
//
// Parallelism model:
//   We parallelize at the MUTATION level, not the word level.
//   For each wordlist word, we apply rules to get N mutations,
//   then hash all N mutations in parallel. This is the right
//   granularity for Argon2 — each hash takes ~100ms+, so
//   N=20 mutations per word keeps all cores busy per word.
//
// Early exit:
//   Rayon's `find_any()` returns as soon as ANY thread finds a
//   match and cancels the remaining work. This is crucial —
//   without early exit we'd keep hashing after finding the answer.
//
// Progress tracking:
//   We use an AtomicU64 counter shared across threads to track
//   how many candidates have been tested. This is read by the
//   progress bar without locking.
// ============================================================

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;

use crate::hashes;
use crate::rules::RuleSet;
use crate::wordlist;


// ============================================================
// CrackResult
//
// The outcome of a crack attempt. Returned by crack() to main.
// ============================================================
#[derive(Debug)]
pub struct CrackResult {
    /// The plaintext password, if found
    pub plaintext: Option<String>,

    /// Total candidates tested (words × mutations)
    pub candidates_tested: u64,

    /// Wall-clock time the crack took
    pub elapsed: std::time::Duration,

    /// Average candidates per second over the run
    pub candidates_per_second: f64,
}


// ============================================================
// crack  (public — called from main.rs)
//
// Runs the full crack attempt and returns a CrackResult.
//
// Arguments:
//   hash         — the hash string to crack
//   algorithm    — "argon2", "bcrypt", or "scrypt"
//   wordlist     — path to the wordlist file
//   ruleset      — which mutations to apply per word
//   total_words  — line count (for progress bar), 0 = unknown
//   show_stats   — if true, show live candidates/sec counter
// ============================================================
pub fn crack(
    hash: &str,
    algorithm: &str,
    wordlist_path: &Path,
    ruleset: &RuleSet,
    total_words: u64,
    show_stats: bool,
) -> CrackResult {

    // --------------------------------------------------------
    // Set up shared state across threads.
    //
    // `Arc` = Atomic Reference Counted — lets multiple threads
    // share ownership of a value. We wrap atomics in Arc so
    // rayon's threads can all increment/read them safely.
    // --------------------------------------------------------

    // Counter: how many candidates have been tested so far
    let counter = Arc::new(AtomicU64::new(0));

    // Flag: set to true when a match is found, so other threads
    // can stop work early even if rayon hasn't cancelled them yet
    let found = Arc::new(AtomicBool::new(false));

    // --------------------------------------------------------
    // Set up the progress bar.
    //
    // Total units = words × mutations per word (approximate).
    // We use the word count × ruleset multiplier as the estimate.
    // --------------------------------------------------------
    let estimated_total = total_words * ruleset.multiplier() as u64;

    let pb = if total_words > 0 {
        let bar = ProgressBar::new(estimated_total);
        bar.set_style(
            ProgressStyle::with_template(
                "{spinner:.cyan} [{bar:40.cyan/blue}] {pos}/{len} candidates {msg}"
            )
            .unwrap()
            .progress_chars("█▓░"),
        );
        Some(bar)
    } else {
        None
    };

    let start_time = Instant::now();

    // --------------------------------------------------------
    // Open the wordlist channel.
    //
    // stream_wordlist() spawns a reader thread and returns a
    // Receiver. We iterate this channel in the crack loop below.
    // --------------------------------------------------------
    let rx = match wordlist::stream_wordlist(wordlist_path) {
        Ok(r)  => r,
        Err(e) => {
            eprintln!("failed to open wordlist: {e}");
            return CrackResult {
                plaintext: None,
                candidates_tested: 0,
                elapsed: start_time.elapsed(),
                candidates_per_second: 0.0,
            };
        }
    };

    // --------------------------------------------------------
    // The crack loop.
    //
    // We iterate wordlist lines from the channel. For each word:
    //   1. Apply the rule engine to get a Vec of mutations
    //   2. Use rayon's par_iter to hash all mutations in parallel
    //   3. find_any() returns the first match (or None)
    //   4. If found, store it and break out of the outer loop
    //
    // `found.load(Ordering::Relaxed)` is checked at the top of
    // each iteration so we stop reading the channel as soon as
    // another thread finds the answer.
    // --------------------------------------------------------
    let mut plaintext: Option<String> = None;

    // Clone Arcs for use inside the loop
    let counter_ref = Arc::clone(&counter);
    let found_ref   = Arc::clone(&found);

    // Stats thread: if --stats is set, spawn a thread that
    // prints candidates/sec every second to the progress bar message.
    let stats_handle = if show_stats {
        let counter_stats = Arc::clone(&counter);
        let found_stats   = Arc::clone(&found);
        Some(std::thread::spawn(move || {
            let mut last_count = 0u64;
            while !found_stats.load(Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_secs(1));
                let current = counter_stats.load(Ordering::Relaxed);
                let rate = current - last_count;
                last_count = current;
                // Print to stderr so it doesn't interfere with JSON output
                eprintln!("  rate: {}/sec", format_number(rate));
            }
        }))
    } else {
        None
    };

    // Main word loop — reads from the channel until it closes
    for word in rx.iter() {
        // Early exit if another iteration already found the answer
        if found_ref.load(Ordering::Relaxed) {
            break;
        }

        // Apply the rule engine to generate candidate mutations
        let candidates = ruleset.apply(&word);
        let candidate_count = candidates.len() as u64;

        // Hash the string and algorithm into the closure.
        // We need owned String because the closure moves into rayon.
        let hash_owned = hash.to_string();
        let alg_owned  = algorithm.to_string();

        // --------------------------------------------------------
        // Parallel verification of all mutations for this word.
        //
        // `par_iter()` — rayon converts the Vec iterator into a
        //   parallel iterator. Each thread in the pool picks up
        //   one mutation to hash.
        //
        // `find_any()` — returns Some(item) as soon as any thread
        //   finds a match, and cancels remaining work. Returns None
        //   if all mutations were checked with no match.
        //
        // The closure takes a reference to each candidate string.
        // --------------------------------------------------------
        let result = candidates
            .par_iter()
            .find_any(|candidate| {
                // Check the found flag inside the parallel loop too.
                // rayon doesn't guarantee instant cancellation, so this
                // avoids doing extra work after a match is found.
                if found_ref.load(Ordering::Relaxed) {
                    return false;
                }
                hashes::verify(candidate, &hash_owned, &alg_owned)
            });

        // Update the counter — Relaxed ordering is fine here because
        // we don't need strict synchronization with other threads,
        // just an approximate count for the progress bar.
        counter_ref.fetch_add(candidate_count, Ordering::Relaxed);

        // Update the progress bar
        if let Some(ref bar) = pb {
            bar.inc(candidate_count);
        }

        // If we found a match, record it and signal other threads
        if let Some(matched) = result {
            plaintext = Some(matched.clone());
            found_ref.store(true, Ordering::Relaxed);
            break;
        }
    }

    // Signal the stats thread to stop (if running)
    found.store(true, Ordering::Relaxed);
    if let Some(handle) = stats_handle {
        let _ = handle.join();
    }

    if let Some(ref bar) = pb {
        bar.finish_and_clear();
    }

    let elapsed = start_time.elapsed();
    let total_tested = counter.load(Ordering::Relaxed);
    let cps = if elapsed.as_secs_f64() > 0.0 {
        total_tested as f64 / elapsed.as_secs_f64()
    } else {
        0.0
    };

    CrackResult {
        plaintext,
        candidates_tested: total_tested,
        elapsed,
        candidates_per_second: cps,
    }
}


// ============================================================
// format_number
//
// Formats a large number with thousands separators for display.
// 1234567 → "1,234,567"
// ============================================================
fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, ch) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(ch);
    }
    result.chars().rev().collect()
}
