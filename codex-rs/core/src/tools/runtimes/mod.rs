/*
Module: runtimes

Concrete ToolRuntime implementations for specific tools. Each runtime stays
small and focused and reuses the orchestrator for approvals + sandbox + retry.
*/
use crate::exec::ExecExpiration;
use crate::sandboxing::CommandSpec;
use crate::sandboxing::SandboxPermissions;
use crate::shell::Shell;
use crate::shell::ShellType;
use crate::tools::sandboxing::ToolError;
use std::collections::HashMap;
use std::path::Path;

pub mod apply_patch;
pub mod shell;
pub mod unified_exec;

/// Shared helper to construct a CommandSpec from a tokenized command line.
/// Validates that at least a program is present.
pub(crate) fn build_command_spec(
    command: &[String],
    cwd: &Path,
    env: &HashMap<String, String>,
    expiration: ExecExpiration,
    sandbox_permissions: SandboxPermissions,
    justification: Option<String>,
) -> Result<CommandSpec, ToolError> {
    let (program, args) = command
        .split_first()
        .ok_or_else(|| ToolError::Rejected("command args are empty".to_string()))?;
    Ok(CommandSpec {
        program: program.clone(),
        args: args.to_vec(),
        cwd: cwd.to_path_buf(),
        env: env.clone(),
        expiration,
        sandbox_permissions,
        justification,
    })
}

/// POSIX-only helper: for commands produced by `Shell::derive_exec_args`
/// for Bash/Zsh/sh of the form `[shell_path, "-lc", "<script>"]`, and
/// when a snapshot is configured on the session shell, rewrite the argv
/// to a single non-login shell that sources the snapshot before running
/// the original script:
///
///   shell -lc "<script>"
///   => shell -c ". SNAPSHOT && <script>"
///
/// On non-POSIX shells or non-matching commands this is a no-op.
pub(crate) fn maybe_wrap_shell_lc_with_snapshot(
    command: &[String],
    session_shell: &Shell,
) -> Vec<String> {
    let Some(snapshot) = &session_shell.shell_snapshot else {
        return command.to_vec();
    };

    if !snapshot.path.exists() {
        return command.to_vec();
    }

    if command.len() < 3 {
        return command.to_vec();
    }

    let flag = command[1].as_str();
    if flag != "-lc" {
        return command.to_vec();
    }

    let mut snapshot_path = snapshot.path.to_string_lossy().to_string();
    if cfg!(windows)
        && matches!(
            session_shell.shell_type,
            ShellType::Zsh | ShellType::Bash | ShellType::Sh
        )
    {
        snapshot_path = snapshot_path.replace('\\', "/");
    }
    let rewritten_script = format!(". \"{snapshot_path}\" && {}", command[2]);

    let mut rewritten = command.to_vec();
    rewritten[1] = "-c".to_string();
    rewritten[2] = rewritten_script;
    rewritten
}

#[cfg(test)]
mod tests {
    use super::maybe_wrap_shell_lc_with_snapshot;
    use crate::shell::Shell;
    use crate::shell::ShellType;
    use crate::shell_snapshot::ShellSnapshot;
    use pretty_assertions::assert_eq;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;
    use tempfile::tempdir;

    #[cfg(windows)]
    #[test]
    fn wraps_snapshot_with_forward_slashes_on_windows_posix_shell() {
        let temp = tempdir().expect("tempdir");
        let snapshot_dir = temp.path().join("snapshots");
        fs::create_dir_all(&snapshot_dir).expect("snapshot dir");
        let snapshot_path = snapshot_dir.join("snapshot.sh");
        fs::write(&snapshot_path, "snapshot").expect("snapshot file");

        let shell = Shell {
            shell_type: ShellType::Bash,
            shell_path: PathBuf::from("bash"),
            shell_snapshot: Some(Arc::new(ShellSnapshot {
                path: snapshot_path.clone(),
            })),
        };

        let command = vec!["bash".to_string(), "-lc".to_string(), "echo hi".to_string()];
        let actual = maybe_wrap_shell_lc_with_snapshot(&command, &shell);

        let expected_path = snapshot_path
            .to_string_lossy()
            .to_string()
            .replace('\\', "/");
        let expected = vec![
            "bash".to_string(),
            "-c".to_string(),
            format!(". \"{expected_path}\" && echo hi"),
        ];

        assert_eq!(actual, expected);
    }
}
