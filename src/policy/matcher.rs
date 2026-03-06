use std::collections::HashMap;

use parking_lot::RwLock;
use serde_json;

use super::types::{CompiledPolicy, PolicyDecision, ToolRule, ToolRuleRaw};

// ---------------------------------------------------------------------------
// PolicyMatcher -- the core policy evaluation engine.
// ---------------------------------------------------------------------------

/// A fast, thread-safe policy matching engine.
///
/// Policies are compiled once per agent and stored in a concurrent hash map.
/// Tool-call checks are performed with deny-first semantics:
///
/// 1. **Deny rules** are evaluated first -- if any deny pattern matches the
///    tool name, the call is immediately denied.
/// 2. **Allow rules** are evaluated next -- the first allow rule whose tool
///    pattern matches is used to validate the call's arguments.
/// 3. If no allow rule matches, the call is denied with a default message.
pub struct PolicyMatcher {
    policies: RwLock<HashMap<String, CompiledPolicy>>,
}

impl PolicyMatcher {
    /// Create a new, empty `PolicyMatcher`.
    pub fn new() -> Self {
        Self {
            policies: RwLock::new(HashMap::new()),
        }
    }

    /// Compile and register a policy for the given agent.
    ///
    /// Both `deny_rules_json` and `allow_rules_json` are JSON arrays of
    /// `ToolRuleRaw` objects.  All glob and regex patterns are compiled
    /// eagerly so that `check_tool_call` is as fast as possible.
    ///
    /// Returns `Ok(())` on success or an error string describing the first
    /// compilation failure.
    pub fn compile_policy(
        &self,
        agent_id: &str,
        deny_rules_json: &str,
        allow_rules_json: &str,
    ) -> Result<(), String> {
        let deny_raw: Vec<ToolRuleRaw> = serde_json::from_str(deny_rules_json)
            .map_err(|e| format!("Failed to parse deny rules JSON: {}", e))?;
        let allow_raw: Vec<ToolRuleRaw> = serde_json::from_str(allow_rules_json)
            .map_err(|e| format!("Failed to parse allow rules JSON: {}", e))?;

        let deny_rules: Vec<ToolRule> = deny_raw
            .iter()
            .map(|r| {
                let mut rule = ToolRule::compile(r)?;
                rule.is_deny = true; // enforce regardless of what the JSON says
                Ok(rule)
            })
            .collect::<Result<Vec<_>, String>>()?;

        let allow_rules: Vec<ToolRule> = allow_raw
            .iter()
            .map(|r| {
                let mut rule = ToolRule::compile(r)?;
                rule.is_deny = false;
                Ok(rule)
            })
            .collect::<Result<Vec<_>, String>>()?;

        let policy = CompiledPolicy {
            deny_rules,
            allow_rules,
        };

        self.policies.write().insert(agent_id.to_string(), policy);

        Ok(())
    }

    /// Remove the compiled policy for an agent, if any.
    pub fn remove_policy(&self, agent_id: &str) -> bool {
        self.policies.write().remove(agent_id).is_some()
    }

    /// Check whether a tool call is permitted under the agent's policy.
    ///
    /// # Arguments
    ///
    /// - `agent_id`  -- the agent whose policy to evaluate.
    /// - `tool_name` -- the name of the tool being invoked.
    /// - `args_json` -- the JSON-encoded arguments to the tool.
    ///
    /// # Deny-first evaluation order
    ///
    /// 1. If the agent has no compiled policy, deny by default.
    /// 2. Iterate the **deny rules** -- if any rule's tool pattern matches
    ///    `tool_name`, immediately return `Denied`.
    /// 3. Iterate the **allow rules** -- the first rule whose tool pattern
    ///    matches is used.  If its argument constraints pass, the call is
    ///    `Allowed`; otherwise `Denied` with the validation reason.
    /// 4. If no allow rule matches, deny with a default message.
    pub fn check_tool_call(
        &self,
        agent_id: &str,
        tool_name: &str,
        args_json: &str,
    ) -> PolicyDecision {
        let policies = self.policies.read();

        let policy = match policies.get(agent_id) {
            Some(p) => p,
            None => {
                return PolicyDecision::Denied(format!(
                    "No policy compiled for agent '{}'",
                    agent_id
                ));
            }
        };

        // ------------------------------------------------------------------
        // Step 1: check deny list.
        // ------------------------------------------------------------------
        for rule in &policy.deny_rules {
            if rule.matches_tool(tool_name) {
                let reason = rule
                    .deny_reason
                    .clone()
                    .unwrap_or_else(|| format!("Tool '{}' is explicitly denied", tool_name));
                return PolicyDecision::Denied(reason);
            }
        }

        // ------------------------------------------------------------------
        // Step 2: parse args once for allow-list validation.
        // ------------------------------------------------------------------
        let args: serde_json::Value = match serde_json::from_str(args_json) {
            Ok(v) => v,
            Err(e) => {
                return PolicyDecision::Denied(format!("Invalid tool args JSON: {}", e));
            }
        };

        // ------------------------------------------------------------------
        // Step 3: check allow list.
        // ------------------------------------------------------------------
        for rule in &policy.allow_rules {
            if rule.matches_tool(tool_name) {
                // Tool name matches an allow rule -- validate arguments.
                return match rule.validate_args(&args) {
                    Ok(()) => PolicyDecision::Allowed,
                    Err(reason) => PolicyDecision::Denied(reason),
                };
            }
        }

        // ------------------------------------------------------------------
        // Step 4: default deny.
        // ------------------------------------------------------------------
        PolicyDecision::Denied(format!("No matching allow rule for tool '{}'", tool_name))
    }

    /// Return the number of agents that currently have compiled policies.
    pub fn policy_count(&self) -> usize {
        self.policies.read().len()
    }

    /// Check whether a compiled policy exists for the given agent.
    pub fn has_policy(&self, agent_id: &str) -> bool {
        self.policies.read().contains_key(agent_id)
    }
}

impl Default for PolicyMatcher {
    fn default() -> Self {
        Self::new()
    }
}

// Make PolicyMatcher safe to share across threads (it already is thanks to
// RwLock, but let's be explicit).
unsafe impl Send for PolicyMatcher {}
unsafe impl Sync for PolicyMatcher {}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_matcher() -> PolicyMatcher {
        let m = PolicyMatcher::new();

        let deny = json!([
            {
                "tool_pattern": "shell_*",
                "is_deny": true,
                "deny_reason": "Shell access is forbidden"
            },
            {
                "tool_pattern": "network_raw",
                "is_deny": true,
                "deny_reason": "Raw network access denied"
            }
        ]);

        let allow = json!([
            {
                "tool_pattern": "file_read",
                "arg_constraints": [
                    {
                        "key": "path",
                        "pattern": "^/tmp/.*$",
                        "max_length": 256
                    }
                ]
            },
            {
                "tool_pattern": "file_list",
                "arg_constraints": []
            },
            {
                "tool_pattern": "http_get",
                "arg_constraints": [
                    {
                        "key": "url",
                        "pattern": "^https://api\\.example\\.com/.*$"
                    }
                ]
            }
        ]);

        m.compile_policy("agent-1", &deny.to_string(), &allow.to_string())
            .expect("compile should succeed");
        m
    }

    #[test]
    fn test_deny_rule_matches() {
        let m = make_matcher();
        let decision = m.check_tool_call("agent-1", "shell_exec", "{}");
        assert_eq!(
            decision,
            PolicyDecision::Denied("Shell access is forbidden".into())
        );
    }

    #[test]
    fn test_allow_rule_passes() {
        let m = make_matcher();
        let args = json!({"path": "/tmp/data.txt"}).to_string();
        let decision = m.check_tool_call("agent-1", "file_read", &args);
        assert_eq!(decision, PolicyDecision::Allowed);
    }

    #[test]
    fn test_allow_rule_arg_validation_fails() {
        let m = make_matcher();
        let args = json!({"path": "/etc/shadow"}).to_string();
        let decision = m.check_tool_call("agent-1", "file_read", &args);
        assert!(matches!(decision, PolicyDecision::Denied(_)));
    }

    #[test]
    fn test_no_matching_allow_rule() {
        let m = make_matcher();
        let decision = m.check_tool_call("agent-1", "database_query", "{}");
        assert!(matches!(decision, PolicyDecision::Denied(_)));
        assert!(decision
            .reason()
            .unwrap()
            .contains("No matching allow rule"));
    }

    #[test]
    fn test_no_policy_for_agent() {
        let m = make_matcher();
        let decision = m.check_tool_call("unknown-agent", "file_read", "{}");
        assert!(matches!(decision, PolicyDecision::Denied(_)));
        assert!(decision.reason().unwrap().contains("No policy compiled"));
    }

    #[test]
    fn test_allow_no_constraints() {
        let m = make_matcher();
        let decision = m.check_tool_call("agent-1", "file_list", "{}");
        assert_eq!(decision, PolicyDecision::Allowed);
    }

    #[test]
    fn test_remove_policy() {
        let m = make_matcher();
        assert!(m.has_policy("agent-1"));
        assert!(m.remove_policy("agent-1"));
        assert!(!m.has_policy("agent-1"));
    }

    #[test]
    fn test_invalid_args_json() {
        let m = make_matcher();
        let _decision = m.check_tool_call("agent-1", "file_list", "NOT JSON");
        // file_list has no arg constraints, but the JSON is still parsed
        // Let's use file_read which has constraints
        let decision2 = m.check_tool_call("agent-1", "file_read", "NOT JSON");
        assert!(matches!(decision2, PolicyDecision::Denied(_)));
    }
}
