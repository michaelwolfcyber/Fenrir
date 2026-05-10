// ============================================================
// output.rs — Result reporting
//
// Handles all terminal output for the crack result.
// Kept separate from cracker.rs so the crack logic stays clean
// and output formatting can be changed independently.
// ============================================================

use colored::*;
use crate::cracker::CrackResult;


// ============================================================
// print_result
//
// Prints the final outcome of a crack attempt.
//
// If the password was found:
//   - Shows the plaintext in green
//   - Shows the hash it came from
//   - Shows timing and throughput stats
//
// If not found:
//   - Says so clearly
//   - Shows how many candidates were tested (useful for verifying
//     the wordlist and rules covered what you expected)
// ============================================================
pub fn print_result(result: &CrackResult, hash: &str) {
    println!();
    println!("{}", "─".repeat(60).truecolor(60, 60, 60));

    match &result.plaintext {
        Some(password) => {
            // CRACKED
            println!("{}", "  PASSWORD FOUND".green().bold());
            println!();
            println!(
                "  {}  {}",
                "plaintext:".truecolor(120, 120, 120),
                password.white().bold(),
            );
            println!(
                "  {}  {}",
                "hash:     ".truecolor(120, 120, 120),
                truncate(hash, 55).yellow(),
            );
        }

        None => {
            // NOT FOUND
            println!("{}", "  PASSWORD NOT FOUND".red().bold());
            println!();
            println!(
                "  {}",
                "The wordlist was exhausted without a match.".truecolor(140, 140, 140)
            );
            println!(
                "  {}",
                "Try a larger wordlist or a more aggressive rule set (--rules full).".truecolor(100, 100, 100)
            );
        }
    }

    // --------------------------------------------------------
    // Stats block — shown regardless of outcome
    // --------------------------------------------------------
    println!();
    println!(
        "  {}  {}",
        "candidates:".truecolor(120, 120, 120),
        format_number(result.candidates_tested).white(),
    );
    println!(
        "  {}  {:.2}s",
        "elapsed:   ".truecolor(120, 120, 120),
        result.elapsed.as_secs_f64(),
    );
    println!(
        "  {}  {}/sec",
        "throughput:".truecolor(120, 120, 120),
        format_number(result.candidates_per_second as u64).cyan(),
    );

    println!("{}", "─".repeat(60).truecolor(60, 60, 60));
}


// ============================================================
// Helpers
// ============================================================

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}...", &s[..max - 3])
    } else {
        s.to_string()
    }
}

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
