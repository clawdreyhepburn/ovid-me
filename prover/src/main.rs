use std::env;
use std::fs;
use std::process;

use cedar_policy::PolicySet;
use serde_json::json;

fn main() {
    let args: Vec<String> = env::args().collect();

    // Expected: agent-authz-prover subset --parent <file> --child <file>
    if args.len() < 6 || args[1] != "subset" {
        eprintln!("Usage: {} subset --parent <parent.cedar> --child <child.cedar>", args[0]);
        process::exit(1);
    }

    let mut parent_path = None;
    let mut child_path = None;
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--parent" => { i += 1; parent_path = Some(&args[i]); }
            "--child"  => { i += 1; child_path = Some(&args[i]); }
            _ => {}
        }
        i += 1;
    }

    let parent_path = parent_path.unwrap_or_else(|| {
        eprintln!("Missing --parent");
        process::exit(1);
    });
    let child_path = child_path.unwrap_or_else(|| {
        eprintln!("Missing --child");
        process::exit(1);
    });

    let parent_src = fs::read_to_string(parent_path).unwrap_or_else(|e| {
        println!("{}", json!({"proven": false, "reason": format!("cannot read parent: {e}")}));
        process::exit(0);
    });
    let child_src = fs::read_to_string(child_path).unwrap_or_else(|e| {
        println!("{}", json!({"proven": false, "reason": format!("cannot read child: {e}")}));
        process::exit(0);
    });

    let parent_ps = match parent_src.parse::<PolicySet>() {
        Ok(ps) => ps,
        Err(e) => {
            println!("{}", json!({"proven": false, "reason": format!("parent parse error: {e}")}));
            process::exit(0);
        }
    };
    let child_ps = match child_src.parse::<PolicySet>() {
        Ok(ps) => ps,
        Err(e) => {
            println!("{}", json!({"proven": false, "reason": format!("child parse error: {e}")}));
            process::exit(0);
        }
    };

    // Structural subset check:
    // For each policy in the child, check if there's a structurally identical policy in the parent.
    // This is conservative — it only proves subset when policies match exactly.
    let parent_texts: Vec<String> = parent_ps.policies().map(|p| normalize_policy(p)).collect();
    let mut uncovered = Vec::new();

    for child_policy in child_ps.policies() {
        let child_norm = normalize_policy(child_policy);
        if !parent_texts.contains(&child_norm) {
            uncovered.push(child_policy.id().to_string());
        }
    }

    if uncovered.is_empty() {
        println!("subset: proven");
        println!("{}", json!({"proven": true}));
    } else {
        println!("{}", json!({
            "proven": false,
            "reason": format!("child policies not covered by parent: {}", uncovered.join(", "))
        }));
    }
}

/// Normalize a policy to a canonical string for comparison.
/// Strips the policy ID and whitespace differences.
fn normalize_policy(policy: &cedar_policy::Policy) -> String {
    // Use the Cedar display format but strip the @id annotation
    let text = policy.to_string();
    // Remove @id("...") lines and normalize whitespace
    let mut lines: Vec<&str> = text.lines()
        .map(|l| l.trim())
        .filter(|l| !l.starts_with("@id(") && !l.is_empty())
        .collect();
    lines.join(" ")
}
