use rayon::prelude::*;

use serde::Deserialize;
use std::collections::HashMap;

/// A function type for context evaluators
type ContextEvaluator = fn() -> Option<String>;

fn detect_python_context() -> Option<String> {
    if std::path::Path::new("requirements.txt").exists()
        || std::path::Path::new("pyproject.toml").exists()
    {
        Some("You are in a Python project. Suggest Python-specific commands.".to_string())
    } else {
        None
    }
}

fn detect_os_context() -> Option<String> {
    if cfg!(target_os = "macos") {
        Some("You are using macOS. Provide macOS-specific commands.".to_string())
    } else if cfg!(target_os = "linux") {
        Some("You are using Linux. Provide Linux-specific commands.".to_string())
    } else if cfg!(target_os = "windows") {
        Some("You are using Windows. Provide Windows-specific commands.".to_string())
    } else {
        None
    }
}

fn detect_docker_context() -> Option<String> {
    let is_docker = std::fs::read_to_string("/proc/1/cgroup")
        .map(|contents| contents.contains("docker"))
        .unwrap_or(false);

    if is_docker {
        Some("You are inside a Docker container. Provide Docker-related commands.".to_string())
    } else {
        None
    }
}

fn detect_git_context() -> Option<String> {
    let current_dir = std::env::current_dir().ok()?;
    let is_git_repo = std::process::Command::new("git")
        .arg("rev-parse")
        .arg("--is-inside-work-tree")
        .current_dir(&current_dir)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false);

    if is_git_repo {
        Some("You are in a Git repository. Provide Git-specific commands.".to_string())
    } else {
        None
    }
}

/// Context-aware prompt generator
pub fn generate_context_aware_prompt() -> String {
    // Context evaluators as a vector of tuples
    let context_evaluators: Vec<(&str, ContextEvaluator)> = vec![
        ("git", detect_git_context),
        ("docker", detect_docker_context),
        ("python", detect_python_context),
        ("os", detect_os_context),
    ];

    // Collect context information from evaluators in parallel
    let context_info: String = context_evaluators
        .par_iter() // Parallel iteration for performance
        .filter_map(|(_, evaluator)| evaluator()) // Run each evaluator
        .collect::<Vec<_>>()
        .join("\n");

    // Format the system prompt for JSON mode
    format!(
        r#"
You are an assistant that provides shell commands as JSON objects. The current context is:
{context_info}

Use the following JSON schema for your responses:
{{
  "bin": "string",                // The command binary (e.g., "git", "docker").
  "subcommand": "string",         // The subcommand, if applicable (e.g., "stash").
  "action": "string",             // The action, if applicable (e.g., "push").
  "flags": [                      // A list of flags and their placeholders.
    {{
      "name": "string",           // The flag (e.g., "-m").
      "placeholder": "string",    // The placeholder for the parameter (e.g., "message").
      "optional": "boolean",      // Whether the flag is optional.
      "default": "string|null"    // Default value if not provided by the user.
    }}
  ]
}}

Always respond strictly in JSON format, adhering to this schema. Do not include any additional text or explanations.

For example:
If the prompt is "stash files" in a Git context, respond with:
{{
  "bin": "git",
  "subcommand": "stash",
  "action": "push",
  "flags": [
    {{
      "name": "-m",
      "placeholder": "message",
      "optional": true,
      "default": null
    }}
  ]
}}

Generate JSON output that strictly adheres to this schema and aligns with the detected context.
"#,
        context_info = context_info.trim()
    )
}

#[cfg(test)]
mod tests {
    use super::*; // Import the context detection functions
    use std::fs;
    use std::path::Path;
    use std::process::Command;
    use tempfile::TempDir;

    /// Test when inside a valid Git repository
    #[test]
    fn test_detect_git_context_inside_repo() {
        // Create a temporary directory
        let temp_dir = TempDir::new().expect("Failed to create temporary directory");
        let test_dir = temp_dir.path();

        // Debug: Print the temp directory path
        println!("Temporary test directory: {:?}", test_dir);

        // Initialize a Git repository in the temp directory
        let output = Command::new("git")
            .arg("init")
            .current_dir(&test_dir)
            .output()
            .expect("Failed to run git command");

        if !output.status.success() {
            panic!(
                "Git init failed with status: {}\nstderr: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
        }

        // Change the current directory to the test Git repo
        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&test_dir).unwrap();

        // Run the function and verify it detects the Git repo
        let result = detect_git_context();
        assert_eq!(
            result,
            Some("You are in a Git repository. Provide Git-specific commands.".to_string())
        );

        // Restore the original directory before temp_dir goes out of scope
        std::env::set_current_dir(original_dir).unwrap();
    }

    /// Test when outside any Git repository
    #[test]
    fn test_detect_git_context_outside_repo() {
        let temp_dir = TempDir::new().expect("Failed to create temporary directory");
        let test_dir = temp_dir.path();

        println!("Temporary directory created at: {:?}", test_dir);

        let original_dir = std::env::current_dir().unwrap();
        if let Err(e) = std::env::set_current_dir(&test_dir) {
            panic!("Failed to change directory to {:?}: {}", test_dir, e);
        }

        // Verify the function's behavior
        let result = detect_git_context();
        assert_eq!(result, None);

        // Restore the original directory
        if let Err(e) = std::env::set_current_dir(&original_dir) {
            panic!("Failed to restore original directory: {}", e);
        }
    }

    /// Test when `.git` directory is incomplete or invalid
    #[test]
    fn test_detect_git_context_invalid_repo() {
        // Create a temporary directory
        let temp_dir = TempDir::new().expect("Failed to create temporary directory");
        let test_dir = temp_dir.path();

        // Create an invalid `.git` directory
        fs::create_dir_all(test_dir.join(".git")).expect("Failed to create .git directory");

        // Change the current directory to the temp directory
        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(&test_dir).unwrap();

        // Run the function and verify it does not detect a valid Git repo
        let result = detect_git_context();
        assert_eq!(result, None);

        // Restore the original directory
        std::env::set_current_dir(original_dir).unwrap();
    }

    /// Test when the `git` command is unavailable
    #[test]
    fn test_detect_git_context_no_git_installed() {
        // Simulate the absence of the `git` command by overriding PATH
        let original_path = std::env::var("PATH").unwrap();
        std::env::set_var("PATH", ""); // Clear the PATH

        let result = detect_git_context();
        assert_eq!(result, None, "Git should not be found");

        // Restore the original PATH
        std::env::set_var("PATH", original_path);
    }
}
