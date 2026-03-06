use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// CompiledPattern -- stores either a glob string, a compiled regex, or both.
// ---------------------------------------------------------------------------

/// A pre-compiled pattern that can match tool names (via glob) or argument
/// values (via regex).  Keeping the original source string around is useful
/// for diagnostics and serialization.
#[derive(Debug, Clone)]
pub struct CompiledPattern {
    /// The original glob pattern string (e.g. `"file.*"`, `"shell_*"`).
    pub glob: Option<String>,
    /// A compiled regular expression for richer matching.
    pub regex: Option<Regex>,
}

impl CompiledPattern {
    /// Create a pattern that only performs glob matching.
    pub fn from_glob(pattern: &str) -> Self {
        Self {
            glob: Some(pattern.to_string()),
            regex: None,
        }
    }

    /// Create a pattern that only performs regex matching.
    pub fn from_regex(pattern: &str) -> Result<Self, regex::Error> {
        let re = Regex::new(pattern)?;
        Ok(Self {
            glob: None,
            regex: Some(re),
        })
    }

    /// Create a pattern with both a glob and a regex component.
    pub fn new(
        glob_pattern: Option<&str>,
        regex_pattern: Option<&str>,
    ) -> Result<Self, regex::Error> {
        let regex = match regex_pattern {
            Some(p) => Some(Regex::new(p)?),
            None => None,
        };
        Ok(Self {
            glob: glob_pattern.map(|s| s.to_string()),
            regex,
        })
    }

    /// Test whether `value` matches this pattern.
    ///
    /// - If a glob is present the value must match the glob.
    /// - If a regex is present the value must match the regex.
    /// - If both are present, **both** must match.
    /// - If neither is present the pattern matches nothing.
    pub fn matches(&self, value: &str) -> bool {
        let glob_ok = match &self.glob {
            Some(g) => glob_match::glob_match(g, value),
            None => true, // no glob constraint -> passes
        };
        let regex_ok = match &self.regex {
            Some(r) => r.is_match(value),
            None => true, // no regex constraint -> passes
        };

        // At least one pattern source must be present for a positive match.
        let has_any = self.glob.is_some() || self.regex.is_some();
        has_any && glob_ok && regex_ok
    }
}

// ---------------------------------------------------------------------------
// ArgConstraint -- constraint on a single argument key.
// ---------------------------------------------------------------------------

/// Describes a constraint on a single argument (identified by JSON key).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ArgConstraint {
    /// The JSON key (dot-path) to look up inside the tool arguments.
    pub key: String,
    /// Optional regex pattern the argument value must match for the rule to
    /// apply (or to pass validation, depending on context).
    #[serde(default)]
    pub pattern: Option<String>,
    /// Optional list of allowed literal values.
    #[serde(default)]
    pub allowed_values: Option<Vec<String>>,
    /// Optional maximum length for string values.
    #[serde(default)]
    pub max_length: Option<usize>,
    /// Optional minimum numeric value.
    #[serde(default)]
    pub min: Option<f64>,
    /// Optional maximum numeric value.
    #[serde(default)]
    pub max: Option<f64>,
}

/// A fully compiled version of `ArgConstraint` that caches the regex.
#[derive(Debug, Clone)]
pub struct CompiledArgConstraint {
    pub key: String,
    pub pattern: Option<CompiledPattern>,
    pub allowed_values: Option<Vec<String>>,
    pub max_length: Option<usize>,
    pub min: Option<f64>,
    pub max: Option<f64>,
}

impl CompiledArgConstraint {
    /// Compile from a raw `ArgConstraint`, turning the pattern string into a
    /// `CompiledPattern` (regex variant).
    pub fn compile(raw: &ArgConstraint) -> Result<Self, regex::Error> {
        let pattern = match &raw.pattern {
            Some(p) => Some(CompiledPattern::from_regex(p)?),
            None => None,
        };
        Ok(Self {
            key: raw.key.clone(),
            pattern,
            allowed_values: raw.allowed_values.clone(),
            max_length: raw.max_length,
            min: raw.min,
            max: raw.max,
        })
    }

    /// Validate a concrete argument value against this constraint.
    /// Returns `Ok(())` on success or `Err(reason)` on failure.
    pub fn validate(&self, value: &serde_json::Value) -> Result<(), String> {
        let value_str = match value {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        };

        // Check max_length.
        if let Some(max) = self.max_length {
            if value_str.len() > max {
                return Err(format!(
                    "Argument '{}' exceeds max length {} (got {})",
                    self.key,
                    max,
                    value_str.len()
                ));
            }
        }

        // Check allowed_values.
        if let Some(ref allowed) = self.allowed_values {
            if !allowed.iter().any(|a| a == &value_str) {
                return Err(format!(
                    "Argument '{}' value '{}' not in allowed values: {:?}",
                    self.key, value_str, allowed
                ));
            }
        }

        // Check regex pattern.
        if let Some(ref pat) = self.pattern {
            if !pat.matches(&value_str) {
                return Err(format!(
                    "Argument '{}' value '{}' does not match required pattern",
                    self.key, value_str
                ));
            }
        }

        // Check min / max (numeric).
        if self.min.is_some() || self.max.is_some() {
            let numeric: f64 = match value {
                serde_json::Value::Number(n) => n.as_f64().ok_or_else(|| {
                    format!(
                        "Argument '{}' must be numeric for min/max validation",
                        self.key
                    )
                })?,
                _ => value_str.parse::<f64>().map_err(|_| {
                    format!(
                        "Argument '{}' must be numeric for min/max validation (got '{}')",
                        self.key, value_str
                    )
                })?,
            };
            if let Some(min_val) = self.min {
                if numeric < min_val {
                    return Err(format!(
                        "Argument '{}' value {} is below minimum {}",
                        self.key, numeric, min_val
                    ));
                }
            }
            if let Some(max_val) = self.max {
                if numeric > max_val {
                    return Err(format!(
                        "Argument '{}' value {} exceeds maximum {}",
                        self.key, numeric, max_val
                    ));
                }
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ToolRule -- a single rule inside a policy.
// ---------------------------------------------------------------------------

/// Raw JSON-friendly representation of a tool rule (deserialized from config).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ToolRuleRaw {
    /// Glob pattern to match tool names (e.g. `"file_*"`, `"shell_exec"`).
    pub tool_pattern: String,
    /// Optional argument constraints.
    #[serde(default)]
    pub arg_constraints: Vec<ArgConstraint>,
    /// Whether this is a deny rule.
    #[serde(default)]
    pub is_deny: bool,
    /// Human-readable reason shown when the rule triggers a deny.
    #[serde(default)]
    pub deny_reason: Option<String>,
}

/// A fully compiled tool rule with pre-built glob/regex matchers.
#[derive(Debug, Clone)]
pub struct ToolRule {
    /// Compiled tool-name pattern (glob).
    pub tool_pattern: CompiledPattern,
    /// Compiled argument constraints.
    pub arg_constraints: Vec<CompiledArgConstraint>,
    /// Whether this is a deny rule.
    pub is_deny: bool,
    /// Reason for denial.
    pub deny_reason: Option<String>,
}

impl ToolRule {
    /// Compile from a raw deserialized rule.
    pub fn compile(raw: &ToolRuleRaw) -> Result<Self, String> {
        let tool_pattern = CompiledPattern::from_glob(&raw.tool_pattern);

        let arg_constraints: Result<Vec<CompiledArgConstraint>, _> = raw
            .arg_constraints
            .iter()
            .map(CompiledArgConstraint::compile)
            .collect();
        let arg_constraints = arg_constraints
            .map_err(|e| format!("Failed to compile arg constraint regex: {}", e))?;

        Ok(Self {
            tool_pattern,
            arg_constraints,
            is_deny: raw.is_deny,
            deny_reason: raw.deny_reason.clone(),
        })
    }

    /// Check if this rule's tool pattern matches the given tool name.
    pub fn matches_tool(&self, tool_name: &str) -> bool {
        self.tool_pattern.matches(tool_name)
    }

    /// Validate tool arguments against all arg constraints in this rule.
    /// Returns `Ok(())` if all constraints pass, or `Err(reason)` on the
    /// first failure.
    pub fn validate_args(&self, args: &serde_json::Value) -> Result<(), String> {
        for constraint in &self.arg_constraints {
            // Resolve the key using dot-path navigation.
            let value = resolve_json_path(args, &constraint.key);
            match value {
                Some(v) => constraint.validate(v)?,
                None => {
                    // Key not found -- treat as a validation failure only if
                    // there are actual constraints to check.
                    if constraint.pattern.is_some()
                        || constraint.allowed_values.is_some()
                        || constraint.max_length.is_some()
                    {
                        return Err(format!("Required argument '{}' is missing", constraint.key));
                    }
                }
            }
        }
        Ok(())
    }
}

/// Navigate a JSON value using a dot-separated path (e.g. `"a.b.c"`).
fn resolve_json_path<'a>(
    value: &'a serde_json::Value,
    path: &str,
) -> Option<&'a serde_json::Value> {
    let mut current = value;
    for segment in path.split('.') {
        match current {
            serde_json::Value::Object(map) => {
                current = map.get(segment)?;
            }
            _ => return None,
        }
    }
    Some(current)
}

// ---------------------------------------------------------------------------
// CompiledPolicy -- the full set of compiled rules for one agent.
// ---------------------------------------------------------------------------

/// Pre-compiled deny and allow rule lists for a single agent.
#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    /// Rules that explicitly deny tool calls.  Evaluated first.
    pub deny_rules: Vec<ToolRule>,
    /// Rules that explicitly allow tool calls.  Evaluated second.
    pub allow_rules: Vec<ToolRule>,
}

impl CompiledPolicy {
    /// Create a new empty policy.
    pub fn new() -> Self {
        Self {
            deny_rules: Vec::new(),
            allow_rules: Vec::new(),
        }
    }
}

impl Default for CompiledPolicy {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// PolicyDecision -- the result of evaluating a tool call against a policy.
// ---------------------------------------------------------------------------

/// The outcome of a policy check against a single tool invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyDecision {
    /// The tool call is allowed to proceed.
    Allowed,
    /// The tool call is denied.
    Denied(String),
    /// The tool call is rate-limited (e.g. too many calls in a window).
    RateLimited(String),
}

impl PolicyDecision {
    /// Returns `true` if the decision permits the tool call.
    pub fn is_allowed(&self) -> bool {
        matches!(self, PolicyDecision::Allowed)
    }

    /// Human-readable label for the decision variant.
    pub fn label(&self) -> &str {
        match self {
            PolicyDecision::Allowed => "allowed",
            PolicyDecision::Denied(_) => "denied",
            PolicyDecision::RateLimited(_) => "rate_limited",
        }
    }

    /// The reason string, if any.
    pub fn reason(&self) -> Option<&str> {
        match self {
            PolicyDecision::Allowed => None,
            PolicyDecision::Denied(r) | PolicyDecision::RateLimited(r) => Some(r),
        }
    }
}

impl fmt::Display for PolicyDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyDecision::Allowed => write!(f, "Allowed"),
            PolicyDecision::Denied(r) => write!(f, "Denied: {}", r),
            PolicyDecision::RateLimited(r) => write!(f, "RateLimited: {}", r),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_compiled_pattern_glob() {
        let pat = CompiledPattern::from_glob("file_*");
        assert!(pat.matches("file_read"));
        assert!(pat.matches("file_write"));
        assert!(!pat.matches("shell_exec"));
    }

    #[test]
    fn test_compiled_pattern_regex() {
        let pat = CompiledPattern::from_regex(r"^shell_\w+$").unwrap();
        assert!(pat.matches("shell_exec"));
        assert!(!pat.matches("file_read"));
    }

    #[test]
    fn test_compiled_pattern_both() {
        let pat = CompiledPattern::new(Some("file_*"), Some(r"^file_read$")).unwrap();
        assert!(pat.matches("file_read"));
        assert!(!pat.matches("file_write")); // glob matches but regex doesn't
    }

    #[test]
    fn test_arg_constraint_validate() {
        let raw = ArgConstraint {
            key: "path".to_string(),
            pattern: Some(r"^/tmp/.*$".to_string()),
            allowed_values: None,
            max_length: Some(256),
        };
        let compiled = CompiledArgConstraint::compile(&raw).unwrap();
        assert!(compiled.validate(&json!("/tmp/foo.txt")).is_ok());
        assert!(compiled.validate(&json!("/etc/passwd")).is_err());
    }

    #[test]
    fn test_resolve_json_path() {
        let val = json!({"a": {"b": {"c": 42}}});
        assert_eq!(resolve_json_path(&val, "a.b.c"), Some(&json!(42)));
        assert_eq!(resolve_json_path(&val, "a.b.d"), None);
    }

    #[test]
    fn test_policy_decision_display() {
        assert_eq!(PolicyDecision::Allowed.to_string(), "Allowed");
        assert_eq!(
            PolicyDecision::Denied("bad tool".into()).to_string(),
            "Denied: bad tool"
        );
    }
}
