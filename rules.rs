// ============================================================
// rules.rs — Mutation rule engine
//
// A wordlist alone is not enough. Real passwords are rarely
// dictionary words verbatim — they're mutations:
//   "wolf" → "W0lf", "wolf123", "Wolf2024!", "w0lf"
//
// The rule engine takes each wordlist candidate and generates
// a set of mutations from it WITHOUT storing them all on disk.
// This is called a "rule-based attack" — it multiplies the
// effective wordlist size by the number of mutations per word.
//
// Rule sets (in order of increasing coverage / time cost):
//   none   — use words exactly as-is (baseline)
//   basic  — case variants + common numeric suffixes
//   leet   — character substitutions (a→4, e→3, etc)
//   full   — all rules combined
//
// The `apply()` method returns an iterator of candidate strings.
// The cracker calls this once per wordlist line.
// ============================================================


// ============================================================
// RuleSet
//
// An enum representing which rules are active.
// The cracker holds one RuleSet for the entire run.
// ============================================================
#[derive(Debug, Clone)]
pub enum RuleSet {
    None,
    Basic,
    Leet,
    Full,
}

impl RuleSet {
    // Parse the CLI --rules string into a RuleSet variant
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "none"  => Ok(RuleSet::None),
            "basic" => Ok(RuleSet::Basic),
            "leet"  => Ok(RuleSet::Leet),
            "full"  => Ok(RuleSet::Full),
            other   => Err(format!(
                "unknown rule set: '{other}'. Use: none, basic, leet, full"
            )),
        }
    }

    // How many candidates does this ruleset generate per word?
    // Used in the startup summary line. Approximate.
    pub fn multiplier(&self) -> usize {
        match self {
            RuleSet::None  => 1,
            RuleSet::Basic => 20,   // ~3 case variants × ~7 suffixes
            RuleSet::Leet  => 5,    // original + 4 substitution patterns
            RuleSet::Full  => 80,   // all combined, with overlap removed
        }
    }

    // --------------------------------------------------------
    // apply
    //
    // Takes one wordlist candidate and returns a Vec of all
    // mutations to try for that candidate.
    //
    // Returns Vec<String> rather than an iterator because the
    // rayon parallel loop needs to own the candidates.
    //
    // Performance note: we pre-allocate with capacity based on
    // the expected mutation count to avoid repeated reallocation.
    // --------------------------------------------------------
    pub fn apply(&self, word: &str) -> Vec<String> {
        // Strip trailing newline/whitespace from wordlist lines
        let word = word.trim();

        // Empty lines produce no candidates
        if word.is_empty() {
            return Vec::new();
        }

        match self {
            RuleSet::None  => vec![word.to_string()],
            RuleSet::Basic => apply_basic(word),
            RuleSet::Leet  => apply_leet(word),
            RuleSet::Full  => apply_full(word),
        }
    }
}


// ============================================================
// apply_basic
//
// Generates case variants and common numeric/symbol suffixes.
//
// Case variants:
//   wolf → wolf, Wolf, WOLF, wOLF (inverted)
//
// Numeric suffixes — these cover the most common patterns
// seen in real password dumps (rockyou analysis):
//   Single digits:  wolf1 through wolf9
//   Common numbers: wolf12, wolf123, wolf1234, wolf12345
//   Years:          wolf2020 through wolf2025
//   Common pins:    wolf0000, wolf1111, wolf9999
//   Symbols:        wolf!, wolf@, wolf#, wolf$
// ============================================================
fn apply_basic(word: &str) -> Vec<String> {
    let mut candidates = Vec::with_capacity(25);

    // Generate the case variants we'll use as bases
    let lower     = word.to_lowercase();
    let upper     = word.to_uppercase();
    let capitalized = capitalize(word);        // Wolf
    let inverted  = invert_case(word);         // wOLF

    // Base forms (no suffix)
    candidates.push(lower.clone());
    candidates.push(capitalized.clone());
    candidates.push(upper.clone());
    candidates.push(inverted.clone());

    // Common suffixes to append to each base
    // These are ranked by frequency in real password leaks
    let suffixes = [
        "1", "2", "3", "123", "1234", "12345",
        "!", "@", "#", "$",
        "2020", "2021", "2022", "2023", "2024", "2025",
        "0", "00", "000", "0000",
        "11", "111", "1111",
        "99", "999", "9999",
    ];

    // Apply suffixes to the lowercase and capitalized forms
    // (most common patterns in practice)
    for suffix in &suffixes {
        candidates.push(format!("{lower}{suffix}"));
        candidates.push(format!("{capitalized}{suffix}"));
    }

    // Deduplicate in case word was already lowercase etc.
    // We use a simple seen-set approach.
    dedup(candidates)
}


// ============================================================
// apply_leet
//
// Leetspeak substitutions. Replaces common letters with
// visually similar numbers/symbols.
//
// Standard leet map:
//   a → 4    e → 3    i → 1    o → 0    s → 5
//   t → 7    b → 8    g → 9    l → 1
//
// We generate multiple variants:
//   - original word
//   - all substitutions applied
//   - partial substitutions (vowels only, consonants only)
//   - leet + capitalized first letter
// ============================================================
fn apply_leet(word: &str) -> Vec<String> {
    let mut candidates = Vec::with_capacity(8);

    let lower = word.to_lowercase();

    // Always include the original
    candidates.push(lower.clone());

    // Full leet substitution — replace every matchable char
    let full_leet = leet_substitute(&lower);
    if full_leet != lower {
        candidates.push(full_leet.clone());
        // Capitalize the leet version too
        candidates.push(capitalize(&full_leet));
    }

    // Vowels-only leet (subtler substitution, harder to detect)
    let vowel_leet = vowel_leet_substitute(&lower);
    if vowel_leet != lower && vowel_leet != full_leet {
        candidates.push(vowel_leet);
    }

    // Original with capitalization
    candidates.push(capitalize(&lower));

    dedup(candidates)
}


// ============================================================
// apply_full
//
// Combines all rule sets: basic case/suffix variants + leet
// substitutions applied to each base form.
//
// This generates the most candidates per word but is also
// the most expensive. Use for targeted attacks on a small
// wordlist, not a 14M line rockyou run.
// ============================================================
fn apply_full(word: &str) -> Vec<String> {
    let mut candidates = Vec::with_capacity(100);

    // Start with basic variants
    let basic = apply_basic(word);
    candidates.extend(basic.iter().cloned());

    // Apply leet to each basic variant
    for base in &basic {
        let leet = leet_substitute(base);
        if leet != *base {
            candidates.push(leet);
        }
    }

    // Common prefixes (less common than suffixes but worth covering)
    let lower = word.to_lowercase();
    for prefix in &["the", "my", "its", "mr", "dr"] {
        candidates.push(format!("{prefix}{lower}"));
        candidates.push(format!("{prefix}{}", capitalize(&lower)));
    }

    dedup(candidates)
}


// ============================================================
// Helper functions
// ============================================================

// Capitalize the first character, lowercase the rest.
// "wOLF" → "Wolf"
fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None    => String::new(),
        Some(c) => c.to_uppercase().to_string() + &chars.as_str().to_lowercase(),
    }
}

// Invert the case of each character.
// "Wolf" → "wOLF"
fn invert_case(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_uppercase() {
                c.to_lowercase().next().unwrap_or(c)
            } else {
                c.to_uppercase().next().unwrap_or(c)
            }
        })
        .collect()
}

// Apply full leetspeak substitution map to a string.
// Input should already be lowercase.
fn leet_substitute(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a' => '4',
            'e' => '3',
            'i' => '1',
            'o' => '0',
            's' => '5',
            't' => '7',
            'b' => '8',
            'g' => '9',
            'l' => '1',
            other => other,
        })
        .collect()
}

// Apply leet substitution to vowels only.
// "wolf" → "w0lf"  (only the 'o' changes)
fn vowel_leet_substitute(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a' => '4',
            'e' => '3',
            'i' => '1',
            'o' => '0',
            'u' => 'u',  // 'u' has no standard leet equivalent
            other => other,
        })
        .collect()
}

// Remove duplicate strings from a Vec while preserving order.
// We use a seen HashSet for O(n) dedup rather than sort+dedup
// which would change the order.
fn dedup(candidates: Vec<String>) -> Vec<String> {
    use std::collections::HashSet;
    let mut seen = HashSet::new();
    candidates
        .into_iter()
        .filter(|c| seen.insert(c.clone()))
        .collect()
}


// ============================================================
// Unit tests
//
// `cargo test` runs these.
// ============================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_none_returns_word_as_is() {
        let rs = RuleSet::None;
        assert_eq!(rs.apply("wolf"), vec!["wolf"]);
    }

    #[test]
    fn test_basic_includes_original_and_capitalized() {
        let rs = RuleSet::Basic;
        let result = rs.apply("wolf");
        assert!(result.contains(&"wolf".to_string()));
        assert!(result.contains(&"Wolf".to_string()));
        assert!(result.contains(&"WOLF".to_string()));
    }

    #[test]
    fn test_basic_includes_numeric_suffixes() {
        let rs = RuleSet::Basic;
        let result = rs.apply("wolf");
        assert!(result.contains(&"wolf123".to_string()));
        assert!(result.contains(&"wolf2024".to_string()));
        assert!(result.contains(&"Wolf1".to_string()));
    }

    #[test]
    fn test_leet_substitution() {
        assert_eq!(leet_substitute("elite"), "3l1t3");
        assert_eq!(leet_substitute("wolf"),  "w0lf");
        assert_eq!(leet_substitute("beast"), "8345t");
    }

    #[test]
    fn test_capitalize() {
        assert_eq!(capitalize("wolf"),  "Wolf");
        assert_eq!(capitalize("WOLF"),  "Wolf");
        assert_eq!(capitalize("wOLF"),  "Wolf");
    }

    #[test]
    fn test_empty_word_produces_no_candidates() {
        let rs = RuleSet::Full;
        assert!(rs.apply("").is_empty());
        assert!(rs.apply("   ").is_empty());
    }

    #[test]
    fn test_no_duplicates_in_output() {
        let rs = RuleSet::Full;
        let result = rs.apply("aaa");
        let unique: std::collections::HashSet<_> = result.iter().collect();
        assert_eq!(result.len(), unique.len(), "duplicates found in rule output");
    }
}
