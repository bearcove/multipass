use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=MULTIPASS_BUILD_COMMIT");

    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let repo = manifest_dir.join("../..");
    if let Some(git_dir) = resolve_git_dir(&repo) {
        for path in git_rerun_inputs(&git_dir) {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }

    let commit = env::var("MULTIPASS_BUILD_COMMIT")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| repository_head(&repo).unwrap_or_else(|| "unknown".into()));
    println!("cargo:rustc-env=MULTIPASS_BUILD_COMMIT={commit}");
}

fn repository_head(repo: &Path) -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repo)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let commit = String::from_utf8(output.stdout).ok()?;
    let commit = commit.trim();
    (!commit.is_empty()).then(|| commit.to_owned())
}

fn git_rerun_inputs(git_dir: &Path) -> Vec<PathBuf> {
    let mut inputs = vec![git_dir.join("HEAD")];
    let common_dir = resolve_common_dir(git_dir);

    if let Ok(head) = fs::read_to_string(git_dir.join("HEAD"))
        && let Some(reference) = head.trim().strip_prefix("ref: ")
    {
        inputs.push(common_dir.join(reference));
        inputs.push(common_dir.join("packed-refs"));
    }

    inputs
}

fn resolve_common_dir(git_dir: &Path) -> PathBuf {
    let Ok(contents) = fs::read_to_string(git_dir.join("commondir")) else {
        return git_dir.to_owned();
    };
    let common_dir = PathBuf::from(contents.trim());
    let common_dir = if common_dir.is_absolute() {
        common_dir
    } else {
        git_dir.join(common_dir)
    };
    fs::canonicalize(&common_dir).unwrap_or(common_dir)
}

fn resolve_git_dir(repo: &Path) -> Option<PathBuf> {
    let dot_git = repo.join(".git");
    if dot_git.is_dir() {
        return Some(dot_git);
    }

    let pointer = fs::read_to_string(&dot_git).ok()?;
    let path = pointer.trim().strip_prefix("gitdir: ")?;
    let git_dir = PathBuf::from(path);
    Some(if git_dir.is_absolute() {
        git_dir
    } else {
        repo.join(git_dir)
    })
}

#[cfg(test)]
mod tests {
    use super::{git_rerun_inputs, resolve_git_dir};
    use std::fs;
    use std::path::{Path, PathBuf};

    fn fixture(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "multipass-server-build-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn write(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, contents).unwrap();
    }

    #[test]
    fn linked_worktree_reruns_on_common_ref_and_packed_refs() {
        let root = fixture("linked-worktree");
        let repo = root.join("repo");
        let common = root.join("common.git");
        let git_dir = common.join("worktrees/feature");
        fs::create_dir_all(&repo).unwrap();
        write(
            &repo.join(".git"),
            &format!("gitdir: {}\n", git_dir.display()),
        );
        write(&git_dir.join("commondir"), "../..\n");
        write(&git_dir.join("HEAD"), "ref: refs/heads/feature\n");
        let common = fs::canonicalize(common).unwrap();

        let resolved = resolve_git_dir(&repo).unwrap();
        let inputs = git_rerun_inputs(&resolved);

        assert_eq!(
            inputs,
            vec![
                git_dir.join("HEAD"),
                common.join("refs/heads/feature"),
                common.join("packed-refs"),
            ]
        );

        fs::remove_dir_all(root).unwrap();
    }
}
