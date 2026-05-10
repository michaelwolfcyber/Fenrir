// ============================================================
// main.rs — Fenrir entry point
//
// Fenrir is a CPU-focused password cracker targeting memory-hard
// hash algorithms: Argon2 (primary), bcrypt, and scrypt.
//
// These algorithms are deliberately slow and memory-hungry,
// which limits GPU parallelism advantage. A fast CPU with many
// cores (like the M4 Pro) is genuinely competitive here.
//
// Program flow:
//   1. Parse CLI arguments
//   2. Load and validate the target hash
//   3. Build the rule set (mutations to apply to each candidate)
//   4. Stream candidates from the wordlist through the rule engine
//   5. Hash each mutated candidate in parallel using rayon
//   6. Report the result when a match is found (or exhaustion)
//
// Module layout:
//   wordlist.rs — reads wordlist files, streams candidates
//   rules.rs    — mutation engine (append digits, case, leet, etc)
//   hashes.rs   — pluggable hash backends (Argon2, bcrypt, scrypt)
//   cracker.rs  — parallel crack loop using rayon
//   output.rs   — terminal output, speed stats, result reporting
// ============================================================

mod cracker;
mod hashes;
mod output;
mod rules;
mod wordlist;

use clap::Parser;
use colored::*;
use std::path::PathBuf;

// ============================================================
// Args — CLI definition
//
// clap's `derive` macro reads this struct and generates all
// argument parsing, help text, and validation automatically.
// ============================================================

/// Fenrir -- CPU-focused password cracker for memory-hard hashes
#[derive(Parser, Debug)]
#[command(
    name = "fenrir",
    about = "Fenrir -- CPU password cracker. Argon2, bcrypt, scrypt.",
    long_about = None
)]
pub struct Args {
    /// The hash string to crack.
    /// Argon2:  $argon2id$v=19$m=65536,t=3,p=4$...
    /// bcrypt:  $2b$12$...
    /// scrypt:  $scrypt$ln=17,r=8,p=1$...
    #[arg(short = 'H', long)]
    pub hash: String,

    /// Path to the wordlist file (one candidate per line).
    /// Example: /usr/share/wordlists/rockyou.txt
    #[arg(short, long)]
    pub wordlist: PathBuf,

    /// Rule set to apply to each wordlist candidate.
    /// Rules mutate each word to generate more candidates without
    /// storing them all on disk.
    ///
    /// Options:
    ///   none      -- use words exactly as they appear
    ///   basic     -- capitalize, append common digits (0-9, 123, 2024...)
    ///   leet      -- substitute a→4, e→3, i→1, o→0, s→5
    ///   full      -- all of the above combined
    #[arg(short, long, default_value = "basic")]
    pub rules: String,

    /// Number of threads to use.
    /// Defaults to the number of logical CPU cores on this machine.
    /// On M4 Pro: 12 performance cores + 4 efficiency cores = 16 total.
    /// For Argon2 cracking, stick to performance cores (12) for best results.
    #[arg(short, long)]
    pub threads: Option<usize>,

    /// Hash algorithm. Fenrir will attempt to auto-detect from the
    /// hash string format, but you can override here.
    /// Options: argon2, bcrypt, scrypt
    #[arg(short, long)]
    pub algorithm: Option<String>,

    /// Show a live candidates-per-second counter.
    /// Slightly reduces throughput due to atomic counter updates.
    #[arg(short, long)]
    pub stats: bool,
}


// ============================================================
// main
// ============================================================

fn main() {
    let args = Args::parse();

    print_banner();

    // --------------------------------------------------------
    // Step 1: Detect the hash algorithm.
    //
    // We inspect the hash string prefix to identify the format.
    // PHC string format (used by Argon2, scrypt) starts with $id$
    // bcrypt uses $2b$ or $2a$ prefix.
    //
    // The user can override with --algorithm if auto-detection fails.
    // --------------------------------------------------------
    let algorithm = match detect_algorithm(&args.hash, args.algorithm.as_deref()) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{} {}", "error:".red().bold(), e);
            std::process::exit(1);
        }
    };

    println!(
        "{} {} {}",
        "algorithm:".truecolor(120, 120, 120),
        algorithm.to_uppercase().cyan().bold(),
        "(auto-detected)".truecolor(80, 80, 80),
    );

    // --------------------------------------------------------
    // Step 2: Parse the rule set.
    //
    // Rules are applied to each wordlist candidate to generate
    // mutations. "basic" might turn "wolf" into:
    //   wolf, Wolf, WOLF, wolf1, wolf2, wolf123, wolf2024, ...
    // --------------------------------------------------------
    let ruleset = match rules::RuleSet::from_str(&args.rules) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{} {}", "error:".red().bold(), e);
            std::process::exit(1);
        }
    };

    println!(
        "{} {} (generates ~{}x candidates per word)",
        "rules:".truecolor(120, 120, 120),
        args.rules.cyan(),
        ruleset.multiplier(),
    );

    // --------------------------------------------------------
    // Step 3: Validate the wordlist file exists and is readable.
    // --------------------------------------------------------
    if !args.wordlist.exists() {
        eprintln!(
            "{} wordlist not found: {}",
            "error:".red().bold(),
            args.wordlist.display()
        );
        std::process::exit(1);
    }

    // Count lines for the progress bar.
    // We do a fast line count pass before cracking starts.
    let line_count = wordlist::count_lines(&args.wordlist).unwrap_or(0);

    println!(
        "{} {} ({} words)",
        "wordlist:".truecolor(120, 120, 120),
        args.wordlist.display().to_string().cyan(),
        line_count.to_string().white().bold(),
    );

    // --------------------------------------------------------
    // Step 4: Configure the rayon thread pool.
    //
    // By default rayon uses all logical cores. For Argon2 we
    // want to tune this — more threads than physical performance
    // cores can hurt throughput because Argon2 is memory-bound
    // and efficiency cores have less cache.
    //
    // The user can override with --threads.
    // --------------------------------------------------------
    let thread_count = args.threads.unwrap_or_else(num_cpus);

    // Build a custom rayon thread pool with our chosen count.
    // This is better than setting the global pool because it
    // scopes the parallelism to our cracking work only.
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(thread_count)
        .build()
        .expect("failed to build thread pool");

    println!(
        "{} {}",
        "threads:".truecolor(120, 120, 120),
        thread_count.to_string().cyan(),
    );

    println!(
        "{} {}\n",
        "target:".truecolor(120, 120, 120),
        truncate_hash(&args.hash).yellow(),
    );

    // --------------------------------------------------------
    // Step 5: Run the cracker inside the rayon thread pool.
    //
    // `pool.install()` runs the closure on the pool's threads.
    // Everything inside here has access to rayon parallelism.
    // --------------------------------------------------------
    let result = pool.install(|| {
        cracker::crack(
            &args.hash,
            &algorithm,
            &args.wordlist,
            &ruleset,
            line_count,
            args.stats,
        )
    });

    // --------------------------------------------------------
    // Step 6: Report the outcome.
    // --------------------------------------------------------
    output::print_result(&result, &args.hash);
}


// ============================================================
// detect_algorithm
//
// Inspects the hash string to identify its format.
// Returns a lowercase algorithm name string.
//
// PHC string format: $<id>$<params>$<salt>$<hash>
//   Argon2id: $argon2id$...
//   Argon2i:  $argon2i$...
//   scrypt:   $scrypt$...
//
// bcrypt: $2b$<cost>$<salt+hash>  or  $2a$...
// ============================================================
fn detect_algorithm(hash: &str, override_alg: Option<&str>) -> Result<String, String> {
    // User override takes precedence
    if let Some(alg) = override_alg {
        let alg = alg.to_lowercase();
        match alg.as_str() {
            "argon2" | "bcrypt" | "scrypt" => return Ok(alg),
            _ => return Err(format!("unknown algorithm: {alg}. Use: argon2, bcrypt, scrypt")),
        }
    }

    // Auto-detect from hash prefix
    if hash.starts_with("$argon2") {
        return Ok("argon2".to_string());
    }
    if hash.starts_with("$2b$") || hash.starts_with("$2a$") || hash.starts_with("$2y$") {
        return Ok("bcrypt".to_string());
    }
    if hash.starts_with("$scrypt$") {
        return Ok("scrypt".to_string());
    }

    Err(format!(
        "could not detect algorithm from hash prefix. \
         Use --algorithm to specify: argon2, bcrypt, scrypt"
    ))
}


// ============================================================
// num_cpus
//
// Returns the number of logical CPUs available.
// We use std::thread::available_parallelism() — stable since
// Rust 1.59, no extra crate needed.
//
// On M4 Pro this returns 16 (12 perf + 4 efficiency cores).
// For Argon2 cracking, 12 is often the sweet spot.
// ============================================================
fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)  // Sane fallback if the syscall fails
}


// ============================================================
// truncate_hash
//
// Hashes can be 100+ characters. We truncate for display so
// the terminal output stays readable.
// ============================================================
fn truncate_hash(hash: &str) -> String {
    if hash.len() > 60 {
        format!("{}...", &hash[..57])
    } else {
        hash.to_string()
    }
}


// ============================================================
// print_banner
// ============================================================
fn print_banner() {
    println!(
        "{}",
        r#"
  ███████╗███████╗███╗   ██╗██████╗ ██╗██████╗
  ██╔════╝██╔════╝████╗  ██║██╔══██╗██║██╔══██╗
  █████╗  █████╗  ██╔██╗ ██║██████╔╝██║██████╔╝
  ██╔══╝  ██╔══╝  ██║╚██╗██║██╔══██╗██║██╔══██╗
  ██║     ███████╗██║ ╚████║██║  ██║██║██║  ██║
  ╚═╝     ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝╚═╝  ╚═╝"#
            .cyan()
    );
    println!(
        "  {}\n",
        "CPU password cracker -- Argon2 / bcrypt / scrypt".truecolor(120, 120, 120)
    );
}
