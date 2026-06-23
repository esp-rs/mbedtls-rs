use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::Path;
use std::{fmt, fs, io};

/// Compile-time user configuration for MbedTLS.
///
/// The user config is not the full MbedTLS config, it's appended to the
/// default config.
///
/// This type and its inherent methods are intentionally `pub(crate)`: the
/// `gen/` tree is only reachable via the `#[path]` import in
/// `mbedtls-rs-sys/build.rs`, so there is no downstream API surface to
/// preserve and tightening visibility eliminates any future call site that
/// could feed unvalidated strings into the C preprocessor template rendered
/// by `Display::fmt`.
#[derive(Debug)]
pub(crate) struct MbedtlsUserConfig {
    options: BTreeMap<Box<str>, Value>,
    includes: Vec<Box<str>>,
}

impl MbedtlsUserConfig {
    /// Creates a new, empty config.
    pub(crate) fn new() -> Self {
        Self {
            options: BTreeMap::new(),
            includes: Vec::new(),
        }
    }

    /// Appends a `#include` directive.
    ///
    /// `header` is rendered verbatim into `#include "{header}"`. To keep
    /// that template injection-safe, the header name must appear in a
    /// strict allowlist; adding a new MbedTLS user header requires an
    /// explicit edit to [`validate_header_path`]. Asserts (panics on bug)
    /// because all callers in `gen/` pass compile-time string constants.
    pub(crate) fn add_include(&mut self, header: &str) -> &mut Self {
        validate_header_path(header);
        self.includes.push(header.into());
        self
    }

    /// Writes the MbedTLS user config to a header file.
    pub(crate) fn write_to_path(&self, path: &Path) -> io::Result<()> {
        let contents = self.to_string();
        fs::write(path, contents)
    }

    /// Appends the MbedTLS user config to an existing header file.
    ///
    /// This can be used to manually append the user config to the default
    /// config header file.
    pub(crate) fn append_to_path(&self, path: &Path) -> io::Result<()> {
        let file = fs::OpenOptions::new()
            .append(true)
            .create(false)
            .open(path)?;
        write!(&file, "{self}")
    }

    /// Sets the value of a config option.
    ///
    /// `ident` is the identifier of the config option, without the `MBEDTLS_`
    /// prefix.
    /// `value` is either a `bool` indicating whether the option is present in
    /// the config, or a string value defining the literal C value of the
    /// option.
    ///
    /// Both `ident` and any literal `value` are rendered verbatim into the
    /// `#define MBEDTLS_{ident} {value}` template, so both are validated
    /// here against an injection-resistant alphabet. See
    /// [`validate_macro_ident`] and [`validate_macro_literal`]. Asserts
    /// because every existing caller in `gen/features.rs` /
    /// `gen/builder.rs` passes a compile-time constant.
    pub(crate) fn set(&mut self, ident: &str, value: impl Into<Value>) -> &mut Self {
        validate_macro_ident(ident);
        let v = value.into();
        if let ValueInner::Literal(lit) = &v.0 {
            validate_macro_literal(lit);
        }
        self.options.insert(ident.into(), v);
        self
    }

    /// The set of effectively-enabled options, as `(ident, value)` pairs.
    ///
    /// Options set to `false` (presence-off) are excluded; presence-on options
    /// map to an empty value, and literal options to their literal text. Two
    /// configs producing the same set compile MbedTLS identically (given the
    /// same upstream base config and includes).
    pub(crate) fn effective_defines(&self) -> BTreeMap<&str, &str> {
        self.options
            .iter()
            .filter_map(|(ident, value)| match &value.0 {
                ValueInner::Presence(false) => None,
                ValueInner::Presence(true) => Some((ident.as_ref(), "")),
                ValueInner::Literal(v) => Some((ident.as_ref(), v.as_ref())),
            })
            .collect()
    }

    /// Human-readable delta of `self` relative to `other`'s effective defines:
    /// `+MBEDTLS_X` for options enabled here but not there, `-MBEDTLS_X` for the
    /// reverse. Empty string when the two are equivalent. Used to explain why a
    /// prebuilt artifact was rejected.
    pub(crate) fn effective_delta(&self, other: &Self) -> String {
        let mine = self.effective_defines();
        let theirs = other.effective_defines();

        let mut parts = Vec::new();
        for ident in mine.keys() {
            if !theirs.contains_key(ident) {
                parts.push(format!("+MBEDTLS_{ident}"));
            }
        }
        for ident in theirs.keys() {
            if !mine.contains_key(ident) {
                parts.push(format!("-MBEDTLS_{ident}"));
            }
        }
        // Same ident, different literal value (e.g. a hook work-area size).
        for (ident, val) in &mine {
            if let Some(other_val) = theirs.get(ident) {
                if val != other_val {
                    parts.push(format!("~MBEDTLS_{ident}"));
                }
            }
        }
        parts.join(", ")
    }
}

impl fmt::Display for MbedtlsUserConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("// Generated by mbedtls-rs-sys. Do not edit manually.\n")?;
        for (ident, value) in &self.options {
            // Always undefine the default definition, if present.
            // Undefining an already undefined option is harmless.
            writeln!(f, "#undef MBEDTLS_{ident}")?;
            if matches!(&value.0, ValueInner::Presence(false)) {
                continue;
            }
            write!(f, "#define MBEDTLS_{ident}")?;
            if let ValueInner::Literal(value) = &value.0 {
                write!(f, " {value}")?;
            }
            f.write_str("\n")?;
        }
        for header in &self.includes {
            writeln!(f, "#include \"{header}\"")?;
        }
        Ok(())
    }
}

/// A MbedTLS config value.
///
/// Used by [`MbedtlsUserConfig`].
#[derive(Debug)]
pub(crate) struct Value(ValueInner);

#[derive(Debug)]
enum ValueInner {
    /// A define with a literal value.
    Literal(Box<str>),
    /// A define whose presence in the config controls a feature.
    Presence(bool),
}

impl From<bool> for Value {
    fn from(value: bool) -> Self {
        Self(ValueInner::Presence(value))
    }
}

impl From<&str> for Value {
    fn from(value: &str) -> Self {
        Self(ValueInner::Literal(value.into()))
    }
}

impl From<String> for Value {
    fn from(value: String) -> Self {
        Self(ValueInner::Literal(value.into()))
    }
}

// ---------------------------------------------------------------------------
// Codegen input validators
//
// `MbedtlsUserConfig::set` and `add_include` render their arguments verbatim
// into C preprocessor directives via the `Display` impl above. To keep that
// template injection-safe even if a future caller forwards user/env input
// into these methods, every string entering the config is gated through one
// of the validators below. They `assert!` rather than return `Result` because
// every current caller in `gen/features.rs` and `gen/builder.rs` passes a
// compile-time string constant; a violation indicates a programmer bug in
// the codegen layer, not a runtime user input failure.
// ---------------------------------------------------------------------------

/// Macro identifier alphabet. Rendered as `MBEDTLS_{ident}` in both `#undef`
/// and `#define` directives; matches the convention of every real MbedTLS
/// config macro.
fn validate_macro_ident(ident: &str) {
    assert!(
        !ident.is_empty()
            && ident
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_'),
        "BUG: invalid MbedTLS config identifier {ident:?}: must be non-empty and match ^[A-Z0-9_]+$",
    );
}

/// Macro literal value validator. Rejects every byte and substring that could
/// either escape the generated `#define MBEDTLS_{ident} {lit}` line (NUL,
/// `\n`, `\r`, `"`, line-continuation `\\`), smuggle additional C directives
/// via comment tokens (`/*`, `*/`, `//`), or form a C trigraph sequence
/// (`??x`) that the preprocessor may translate back into `\` line-continuation
/// or other directive-altering characters under modes that honour trigraphs.
fn validate_macro_literal(lit: &str) {
    let single_byte_ok = lit
        .bytes()
        .all(|b| !matches!(b, 0 | b'\n' | b'\r' | b'"' | b'\\'));
    assert!(
        single_byte_ok,
        "BUG: invalid MbedTLS config literal {lit:?}: must not contain NUL, newline, carriage return, double-quote, or backslash",
    );
    assert!(
        !lit.contains("/*"),
        "BUG: invalid MbedTLS config literal {lit:?}: must not contain `/*`",
    );
    assert!(
        !lit.contains("*/"),
        "BUG: invalid MbedTLS config literal {lit:?}: must not contain `*/`",
    );
    assert!(
        !lit.contains("//"),
        "BUG: invalid MbedTLS config literal {lit:?}: must not contain `//`",
    );
    assert!(
        !lit.contains("??"),
        "BUG: invalid MbedTLS config literal {lit:?}: must not contain `??` (trigraph prefix is forbidden)",
    );
}

/// Header path validator. Strict allowlist of known-good MbedTLS user
/// headers. Add new entries here when (and only when) a new hook requires
/// them; the explicit edit is the point: every new include is
/// reviewer-visible.
///
/// `sha{1,256,512}_alt.h` are NOT in this allowlist because MbedTLS's `_ALT`
/// mechanism pulls them in automatically via the `-I gen/hook/` compiler flag
/// added in `MbedtlsBuilder::compile` (gen/builder.rs:397) whenever
/// `MBEDTLS_SHA{1,256,512}_ALT` is defined; those headers never go through
/// `add_include`. Only `time_alt.h` requires an explicit user-config
/// `#include` because the platform-time hook has no equivalent auto-include
/// path (see `builder.rs` `Hook::includes`).
fn validate_header_path(header: &str) {
    assert!(
        matches!(header, "time_alt.h"),
        "BUG: header {header:?} is not in the codegen allowlist; add it explicitly to gen/config.rs::validate_header_path",
    );
}

#[cfg(test)]
mod tests {
    //! Validator tests. Executed via the `mbedtls-rs-sys/tests/config_validators.rs`
    //! integration test, which `#[path]`-loads this module so the `pub(crate)`
    //! API becomes test-crate-local and reachable. Each negative case uses
    //! `#[should_panic(expected = ...)]` to confirm the validator emits the
    //! expected error pattern; positive cases just assert the call returns.

    use super::MbedtlsUserConfig;

    // ---- positive cases ----

    #[test]
    fn accepts_uppercase_ident_presence() {
        MbedtlsUserConfig::new().set("FOO", true);
    }

    #[test]
    fn accepts_digits_and_underscores_in_ident() {
        MbedtlsUserConfig::new().set("FOO_BAR_123", true);
    }

    #[test]
    fn accepts_literal_value() {
        MbedtlsUserConfig::new().set("FOO", "0x10");
    }

    #[test]
    fn accepts_string_literal_value() {
        MbedtlsUserConfig::new().set("FOO", String::from("mbedtls_sec_time"));
    }

    #[test]
    fn accepts_allowlisted_header() {
        MbedtlsUserConfig::new().add_include("time_alt.h");
    }

    // ---- ident rejection cases ----

    #[test]
    #[should_panic(expected = "invalid MbedTLS config identifier")]
    fn rejects_lowercase_ident() {
        MbedtlsUserConfig::new().set("foo", true);
    }

    #[test]
    #[should_panic(expected = "invalid MbedTLS config identifier")]
    fn rejects_ident_with_space() {
        MbedtlsUserConfig::new().set("FOO BAR", true);
    }

    #[test]
    #[should_panic(expected = "invalid MbedTLS config identifier")]
    fn rejects_ident_with_newline() {
        MbedtlsUserConfig::new().set("FOO\n", true);
    }

    #[test]
    #[should_panic(expected = "invalid MbedTLS config identifier")]
    fn rejects_ident_with_quote() {
        MbedtlsUserConfig::new().set("FOO\"", true);
    }

    #[test]
    #[should_panic(expected = "invalid MbedTLS config identifier")]
    fn rejects_empty_ident() {
        MbedtlsUserConfig::new().set("", true);
    }

    #[test]
    #[should_panic(expected = "invalid MbedTLS config identifier")]
    fn rejects_ident_with_hyphen() {
        MbedtlsUserConfig::new().set("FOO-BAR", true);
    }

    // ---- literal rejection cases ----

    #[test]
    #[should_panic(expected = "invalid MbedTLS config literal")]
    fn rejects_literal_with_newline() {
        MbedtlsUserConfig::new().set("FOO", "1\n#undef SOMETHING");
    }

    #[test]
    #[should_panic(expected = "invalid MbedTLS config literal")]
    fn rejects_literal_with_quote() {
        MbedtlsUserConfig::new().set("FOO", "\"escape");
    }

    #[test]
    #[should_panic(expected = "invalid MbedTLS config literal")]
    fn rejects_literal_with_backslash() {
        // A trailing backslash in C splices the generated line with the next
        // one, which would commute the following codegen output into the
        // preceding `#define`.
        MbedtlsUserConfig::new().set("FOO", "1\\");
    }

    #[test]
    #[should_panic(expected = "invalid MbedTLS config literal")]
    fn rejects_literal_with_nul() {
        MbedtlsUserConfig::new().set("FOO", "ab\0cd");
    }

    #[test]
    #[should_panic(expected = "must not contain `/*`")]
    fn rejects_literal_with_block_comment_open() {
        MbedtlsUserConfig::new().set("FOO", "1 /* hi */");
    }

    #[test]
    #[should_panic(expected = "must not contain `*/`")]
    fn rejects_literal_with_block_comment_close() {
        MbedtlsUserConfig::new().set("FOO", "1*/");
    }

    #[test]
    #[should_panic(expected = "must not contain `//`")]
    fn rejects_literal_with_line_comment() {
        MbedtlsUserConfig::new().set("FOO", "1 // injected");
    }

    #[test]
    #[should_panic(expected = "must not contain `??`")]
    fn rejects_literal_with_trigraph_backslash() {
        // `??/` is the C trigraph for `\`. A literal ending in `??/` would
        // line-continue the generated `#define MBEDTLS_FOO 1??/\n` into the
        // next codegen line under any toolchain mode that honours trigraphs.
        MbedtlsUserConfig::new().set("FOO", "1??/");
    }

    #[test]
    #[should_panic(expected = "must not contain `??`")]
    fn rejects_literal_with_trigraph_hash() {
        // `??=` is the C trigraph for `#`. Less directly exploitable than
        // `??/` (a mid-line `#` is just a token in C), but symmetrically
        // forbidden by the `??` substring rule.
        MbedtlsUserConfig::new().set("FOO", "1??=");
    }

    #[test]
    #[should_panic(expected = "must not contain `??`")]
    fn rejects_literal_with_trigraph_pipe() {
        // `??!` is the C trigraph for `|`. Same `??` substring rule.
        MbedtlsUserConfig::new().set("FOO", "1??!");
    }

    #[test]
    #[should_panic(expected = "invalid MbedTLS config literal")]
    fn rejects_literal_with_carriage_return() {
        MbedtlsUserConfig::new().set("FOO", "1\r#undef X");
    }

    // ---- header rejection cases ----

    #[test]
    #[should_panic(expected = "not in the codegen allowlist")]
    fn rejects_unknown_header() {
        MbedtlsUserConfig::new().add_include("other.h");
    }

    #[test]
    #[should_panic(expected = "not in the codegen allowlist")]
    fn rejects_traversal_header() {
        MbedtlsUserConfig::new().add_include("../etc/passwd");
    }

    #[test]
    #[should_panic(expected = "not in the codegen allowlist")]
    fn rejects_absolute_header() {
        MbedtlsUserConfig::new().add_include("/etc/passwd.h");
    }

    #[test]
    #[should_panic(expected = "not in the codegen allowlist")]
    fn rejects_empty_header() {
        MbedtlsUserConfig::new().add_include("");
    }

    #[test]
    #[should_panic(expected = "not in the codegen allowlist")]
    fn rejects_quote_injection_header() {
        MbedtlsUserConfig::new().add_include("foo\"\n#include \"/etc/passwd");
    }

    // ---- render sanity (validated input round-trips correctly) ----

    #[test]
    fn renders_validated_input() {
        let mut c = MbedtlsUserConfig::new();
        c.set("FOO_BAR", true)
            .set("BAZ", "0x42")
            .add_include("time_alt.h");
        let s = c.to_string();
        assert!(s.contains("#define MBEDTLS_FOO_BAR\n"), "{s}");
        assert!(s.contains("#define MBEDTLS_BAZ 0x42\n"), "{s}");
        assert!(s.contains("#include \"time_alt.h\"\n"), "{s}");
    }
}
