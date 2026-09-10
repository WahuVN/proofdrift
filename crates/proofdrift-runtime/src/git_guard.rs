use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GitIntent {
    ReadOnly,
    Commit,
    ResetHard,
    CleanPreview,
    CleanDestructive,
    Checkout,
    CheckoutDestructive,
    Push,
    ForcePush,
    TagCreate,
    TagMutation,
    OtherMutating,
}

impl GitIntent {
    pub fn capability(self) -> &'static str {
        match self {
            Self::ReadOnly | Self::CleanPreview => "git.read",
            Self::Commit => "git.commit",
            Self::Push => "git.push",
            Self::ForcePush => "git.force_push",
            Self::ResetHard
            | Self::CleanDestructive
            | Self::CheckoutDestructive
            | Self::TagMutation => "git.destructive",
            Self::Checkout | Self::TagCreate | Self::OtherMutating => "git.write",
        }
    }

    pub fn is_dangerous(self) -> bool {
        matches!(
            self,
            Self::ResetHard
                | Self::CleanDestructive
                | Self::CheckoutDestructive
                | Self::ForcePush
                | Self::TagMutation
        )
    }
}

pub fn classify_git_argv(argv: &[String]) -> GitIntent {
    let args = strip_git_program(argv);
    let Some(command) = args.first().map(String::as_str) else {
        return GitIntent::ReadOnly;
    };
    let rest = &args[1..];
    match command {
        "status" | "log" | "show" | "diff" | "rev-parse" | "ls-files" | "cat-file" | "grep" => {
            GitIntent::ReadOnly
        }
        "branch" if rest.is_empty() || has_flag(rest, "--list") => GitIntent::ReadOnly,
        "branch" if has_flag(rest, "-d") || has_flag(rest, "-D") => GitIntent::TagMutation,
        "branch" => GitIntent::OtherMutating,
        "remote" if rest.is_empty() || rest.first().map(String::as_str) == Some("show") => {
            GitIntent::ReadOnly
        }
        "remote" => GitIntent::OtherMutating,
        "commit" => GitIntent::Commit,
        "reset" if has_flag(rest, "--hard") => GitIntent::ResetHard,
        "reset" => GitIntent::OtherMutating,
        "clean" if has_force_flag(rest) => GitIntent::CleanDestructive,
        "clean" => GitIntent::CleanPreview,
        "checkout" if has_force_flag(rest) || has_path_checkout(rest) => {
            GitIntent::CheckoutDestructive
        }
        "checkout" | "switch" => GitIntent::Checkout,
        "restore" if has_flag(rest, "--worktree") || !has_flag(rest, "--staged") => {
            GitIntent::CheckoutDestructive
        }
        "restore" => GitIntent::OtherMutating,
        "push" if has_force_push_flag(rest) => GitIntent::ForcePush,
        "push" => GitIntent::Push,
        "tag" if has_flag(rest, "-d") || has_flag(rest, "--delete") || has_force_flag(rest) => {
            GitIntent::TagMutation
        }
        "tag" if rest.iter().any(|arg| !arg.starts_with('-')) => GitIntent::TagCreate,
        "tag" => GitIntent::ReadOnly,
        "add" | "rm" | "mv" | "merge" | "rebase" | "cherry-pick" | "revert" | "stash" => {
            GitIntent::OtherMutating
        }
        _ => GitIntent::OtherMutating,
    }
}

fn strip_git_program(argv: &[String]) -> &[String] {
    if argv
        .first()
        .map(|arg| {
            let lower = arg.to_ascii_lowercase();
            lower == "git" || lower.ends_with("/git") || lower.ends_with("\\git.exe")
        })
        .unwrap_or(false)
    {
        &argv[1..]
    } else {
        argv
    }
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|arg| arg == flag)
}

fn has_force_flag(args: &[String]) -> bool {
    args.iter().any(|arg| {
        arg == "-f"
            || arg == "--force"
            || (arg.starts_with('-') && !arg.starts_with("--") && arg[1..].contains('f'))
    })
}

fn has_force_push_flag(args: &[String]) -> bool {
    has_force_flag(args)
        || args.iter().any(|arg| {
            arg == "--force-with-lease"
                || arg.starts_with("--force-with-lease=")
                || arg == "--force-if-includes"
        })
        || args
            .iter()
            .any(|arg| arg.starts_with('+') && arg.contains(':'))
}

fn has_path_checkout(args: &[String]) -> bool {
    args.iter()
        .position(|arg| arg == "--")
        .map(|idx| idx + 1 < args.len())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn identifies_dangerous_git_operations() {
        assert_eq!(
            classify_git_argv(&v(&["git", "reset", "--hard", "HEAD~1"])),
            GitIntent::ResetHard
        );
        assert_eq!(
            classify_git_argv(&v(&["git", "clean", "-fdx"])),
            GitIntent::CleanDestructive
        );
        assert_eq!(
            classify_git_argv(&v(&["git", "checkout", "--", "src/lib.rs"])),
            GitIntent::CheckoutDestructive
        );
        assert_eq!(
            classify_git_argv(&v(&["git", "push", "--force-with-lease"])),
            GitIntent::ForcePush
        );
        assert_eq!(
            classify_git_argv(&v(&["git", "push", "+HEAD:main"])),
            GitIntent::ForcePush
        );
        assert_eq!(
            classify_git_argv(&v(&["git", "tag", "-d", "v1"])),
            GitIntent::TagMutation
        );
    }

    #[test]
    fn read_only_and_preview_are_not_overclassified() {
        assert_eq!(
            classify_git_argv(&v(&["git", "status", "--short"])),
            GitIntent::ReadOnly
        );
        assert_eq!(
            classify_git_argv(&v(&["git", "clean", "-n"])),
            GitIntent::CleanPreview
        );
        assert_eq!(
            classify_git_argv(&v(&["git", "tag", "--list"])),
            GitIntent::ReadOnly
        );
    }
}
