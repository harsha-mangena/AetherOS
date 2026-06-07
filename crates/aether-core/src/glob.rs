//! Minimal, dependency-free glob matching for policy scope and tool patterns.
//!
//! Policy rules match request scopes and tool names using simple glob patterns. We
//! deliberately implement a tiny, well-understood matcher rather than pulling a regex
//! or glob crate into the security-critical core: smaller attack surface, no surprise
//! backtracking, and behavior we fully control and test.
//!
//! Supported syntax:
//!   `*`  matches any run of characters (including an empty run), within the whole
//!        string. It does not stop at any separator — `s3:read:*` matches
//!        `s3:read:logs` and `s3:read:a:b`.
//!   `?`  matches exactly one character.
//! All other characters match literally. There is no escaping; scope/tool tokens in
//! AetherOS never contain `*` or `?`, so escaping is unnecessary.

/// Returns true if `text` matches the glob `pattern`.
///
/// Implemented as an iterative two-pointer wildcard match with backtracking on `*`,
/// which is linear in practice for these short strings and has no pathological cases.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();

    let mut pi = 0usize; // index into pattern
    let mut ti = 0usize; // index into text
    let mut star_pi: Option<usize> = None; // last '*' position in pattern
    let mut star_ti = 0usize; // text position when last '*' was seen

    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star_pi = Some(pi);
            star_ti = ti;
            pi += 1;
        } else if let Some(spi) = star_pi {
            // Mismatch: backtrack to the last '*', consuming one more text char.
            pi = spi + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }

    // Consume any trailing '*' in the pattern.
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }

    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::glob_match;

    #[test]
    fn literal_match() {
        assert!(glob_match("log_search", "log_search"));
        assert!(!glob_match("log_search", "metrics_query"));
    }

    #[test]
    fn star_matches_suffix() {
        assert!(glob_match("s3:read:*", "s3:read:logs"));
        assert!(glob_match("s3:read:*", "s3:read:a:b:c"));
        assert!(!glob_match("s3:read:*", "s3:write:logs"));
    }

    #[test]
    fn star_matches_empty_run() {
        assert!(glob_match("s3:read:*", "s3:read:"));
        assert!(glob_match("*", ""));
    }

    #[test]
    fn star_in_middle() {
        assert!(glob_match("*:delete:*", "db:delete:prod"));
        assert!(glob_match("*:delete:*", "fs:delete:tmp"));
        assert!(!glob_match("*:delete:*", "db:read:prod"));
    }

    #[test]
    fn question_matches_single_char() {
        assert!(glob_match("a?c", "abc"));
        assert!(!glob_match("a?c", "ac"));
        assert!(!glob_match("a?c", "abbc"));
    }

    #[test]
    fn bare_star_matches_anything() {
        assert!(glob_match("*", "anything:at:all"));
    }

    #[test]
    fn multiple_stars() {
        assert!(glob_match("a*b*c", "axxbyyc"));
        assert!(!glob_match("a*b*c", "axxbyy"));
    }
}
