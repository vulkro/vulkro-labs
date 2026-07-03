//! Self-contained confusable / mixed-script check for agent and provider names.
//!
//! Kept local (not shared with verify::lookalike) because that module is
//! package-ecosystem and top-list scoped, while this is intra-name: it flags a
//! name that mixes Latin with Cyrillic or Greek letters, or whose confusable
//! skeleton collapses onto a different-looking ASCII form. A pure single-script
//! non-Latin name is NOT flagged (only the impersonation tells are).

/// Fold a known confusable character to its Latin lookalike, else lowercase.
fn fold_char(c: char) -> char {
    match c {
        // Cyrillic lookalikes
        'а' => 'a', 'е' => 'e', 'о' => 'o', 'р' => 'p', 'с' => 'c', 'х' => 'x',
        'у' => 'y', 'к' => 'k', 'м' => 'm', 'т' => 't', 'в' => 'b', 'н' => 'h',
        'і' => 'i', 'ѕ' => 's', 'ј' => 'j', 'ԁ' => 'd', 'ɡ' => 'g',
        // Greek lookalikes
        'ο' => 'o', 'α' => 'a', 'ρ' => 'p', 'ε' => 'e', 'ν' => 'v', 'κ' => 'k',
        'τ' => 't', 'υ' => 'u', 'χ' => 'x', 'ι' => 'i',
        // Fullwidth Latin
        'ａ'..='ｚ' => char_from_u32_or(c, c as u32 - 'ａ' as u32 + 'a' as u32),
        _ => c.to_ascii_lowercase(),
    }
}

/// Best-effort char from a scalar value, falling back to the original.
fn char_from_u32_or(fallback: char, code: u32) -> char {
    char::from_u32(code).unwrap_or(fallback)
}

/// The confusable skeleton of a name (confusables folded to Latin, lowercased).
pub fn skeleton(s: &str) -> String {
    s.chars().map(fold_char).collect()
}

fn is_cyrillic(c: char) -> bool {
    ('\u{0400}'..='\u{04FF}').contains(&c)
}

fn is_greek(c: char) -> bool {
    ('\u{0370}'..='\u{03FF}').contains(&c)
}

/// Whether a name mixes Latin with Cyrillic or Greek letters, a classic
/// impersonation trick.
pub fn is_mixed_script(s: &str) -> bool {
    let mut has_latin = false;
    let mut has_confusable_script = false;
    for c in s.chars() {
        if c.is_ascii_alphabetic() {
            has_latin = true;
        } else if is_cyrillic(c) || is_greek(c) {
            has_confusable_script = true;
        }
    }
    has_latin && has_confusable_script
}

/// A confusable finding for a name: Some((raw, folded)) when the name mixes
/// scripts, or its skeleton collapses onto a different all-ASCII form.
pub fn confusable(name: &str) -> Option<(String, String)> {
    let folded = skeleton(name);
    let raw_lower = name.to_lowercase();
    if is_mixed_script(name) || (folded != raw_lower && folded.is_ascii()) {
        Some((name.to_string(), folded))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cyrillic_homoglyph_is_flagged() {
        // 'miсrosoft' uses a Cyrillic 'с' (U+0441).
        let hit = confusable("miсrosoft").expect("a confusable");
        assert_eq!(hit.1, "microsoft");
    }

    #[test]
    fn plain_ascii_name_is_clean() {
        assert!(confusable("weather-bot").is_none());
    }

    #[test]
    fn mixed_script_detection() {
        // 'paypаl' uses a Cyrillic 'а' (U+0430).
        assert!(is_mixed_script("paypаl"));
        assert!(!is_mixed_script("paypal"));
    }

    #[test]
    fn pure_non_latin_is_not_flagged() {
        // A genuinely Greek word (single script) is not an impersonation tell.
        assert!(!is_mixed_script("λογος"));
    }
}
