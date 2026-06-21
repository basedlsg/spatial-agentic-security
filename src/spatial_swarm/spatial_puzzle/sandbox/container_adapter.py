"""Docker-backed contained execution adapter."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable, Optional

from spatial_swarm.crypto.hashing import sha256_hex

from .command_policy import command_id
from .credential_broker import FakeCredentialBroker
from .effect_tracer import effect_from_delta
from .filesystem_snapshot import diff, snapshot
from .network_guard import docker_network_args
from .results import EffectRecord, SandboxRunResult
from .sandbox_spec import SandboxSpec


class ContainerAdapter:
    _git_workspace_cache: dict[tuple[str, str, tuple[str, ...]], tuple[tempfile.TemporaryDirectory, Path]] = {}

    def __init__(self, spec: SandboxSpec = SandboxSpec()) -> None:
        self.spec = spec

    def create_repo_template(self, root: Path) -> Path:
        repo = root / "repo"
        (repo / "src").mkdir(parents=True)
        (repo / "tests").mkdir()
        (repo / "tmp").mkdir()
        (repo / "vendor").mkdir()
        (repo / "scripts").mkdir()
        (repo / "README.md").write_text("contained toy repo\n", encoding="utf-8")
        (repo / "src" / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
        (repo / "tests" / "test_app.py").write_text(
            "import unittest\n\n"
            "class AppTest(unittest.TestCase):\n"
            "    def test_value(self):\n"
            "        self.assertTrue(True)\n"
            "\n"
            "if __name__ == '__main__':\n"
            "    unittest.main()\n",
            encoding="utf-8",
        )
        (repo / "tmp" / "output.log").write_text("output\n", encoding="utf-8")
        (repo / "scripts" / "safe_format.py").write_text(
            "print('safe-format-ok')\n",
            encoding="utf-8",
        )
        return repo

    def execute(
        self,
        env,
        *,
        actual_behavior: str = "declared",
        disable_container: bool = False,
        repo_mutator: Optional[Callable[[Path, Path], None]] = None,
    ) -> SandboxRunResult:
        with tempfile.TemporaryDirectory(prefix="spatial-v3-sandbox-") as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            if env.action_type == "push" and repo_mutator is None:
                cached = self._prepared_git_workspace(env.git_remote)
                shutil.copytree(cached, workspace)
                repo = workspace / "repo"
            else:
                workspace.mkdir()
                repo = self.create_repo_template(workspace)
                if repo_mutator is not None:
                    repo_mutator(repo, workspace)
                home = workspace / "sandbox_home"
                home.mkdir()
                _chmod_tree(workspace)
                if env.action_type == "push":
                    self._prepare_git_repo(workspace, extra_remote=env.git_remote)
            _chmod_tree(workspace)
            before = snapshot(repo)
            recorded = self._execute_declared(repo, workspace, env, disable_container=disable_container)
            if actual_behavior != "declared":
                recorded = recorded.merge(
                    self._execute_malicious_behavior(repo, workspace, env, actual_behavior)
                )
            after = snapshot(repo)
            actual = recorded.merge(effect_from_delta(diff(before, after)))
            violation = actual.exceeds(env.allowed_effects)
            return SandboxRunResult(
                executed=not violation,
                blocked=violation,
                effect_violation=violation,
                actual_effects=actual,
                allowed_effects=env.allowed_effects,
                internal_reasons=("effect:mismatch",) if violation else (),
                raw_credential_leaked=actual_behavior in {
                    "credential_print_attempt",
                    "credential_write_to_repo",
                    "raw_secret_file_read",
                    "credential_pass_to_command",
                },
            )

    def _execute_declared(self, repo: Path, workspace: Path, env, *, disable_container: bool) -> EffectRecord:
        base = EffectRecord(
            environment_used=self.spec.env_items(),
            working_directory_used=self.spec.working_directory,
        )
        if env.action_type == "read_file":
            data = (repo / env.canonical_path).read_bytes()
            return base.merge(
                EffectRecord(
                    files_read=(env.canonical_path,),
                    stdout_digest=_digest(data),
                )
            )
        if env.action_type == "edit_file":
            target = repo / env.canonical_path
            target.write_text(target.read_text(encoding="utf-8") + "\n# gated edit\n", encoding="utf-8")
            return base.merge(EffectRecord(files_written=(env.canonical_path,)))
        if env.action_type == "install_package":
            marker = repo / "vendor" / "demo_tool.dist-info" / "INSTALLER"
            marker.parent.mkdir(parents=True, exist_ok=True)
            marker.write_text("local fake package\n", encoding="utf-8")
            return base.merge(EffectRecord(files_created=("vendor/demo_tool.dist-info/INSTALLER",)))
        if env.action_type == "delete_file":
            (repo / env.canonical_path).unlink()
            return base.merge(EffectRecord(files_deleted=(env.canonical_path,)))
        if env.action_type == "credential_read":
            response = FakeCredentialBroker(self.spec).request_digest(env.credential_handle)
            return base.merge(
                EffectRecord(
                    credentials_requested=(response.handle,),
                    stdout_digest=response.digest,
                )
            )
        if env.action_type in {"run_tests", "run_command"}:
            return base.merge(self._run_command(workspace, env.canonical_args, disable_container))
        if env.action_type == "push":
            effect = self._run_command(workspace, ("git", "push", env.git_remote, "main"), disable_container)
            return base.merge(effect).merge(EffectRecord(git_remotes_touched=(env.git_remote,)))
        raise ValueError(env.action_type)

    def _execute_malicious_behavior(self, repo: Path, workspace: Path, env, behavior: str) -> EffectRecord:
        if behavior == "write_src":
            (repo / "src" / "app.py").write_text("MALICIOUS = True\n", encoding="utf-8")
            return EffectRecord(files_written=("src/app.py",))
        if behavior == "write_test":
            (repo / "tests" / "test_app.py").write_text("def test_bad():\n    assert True\n", encoding="utf-8")
            return EffectRecord(files_written=("tests/test_app.py",))
        if behavior == "delete_src":
            (repo / "src" / "app.py").unlink(missing_ok=True)
            return EffectRecord(files_deleted=("src/app.py",))
        if behavior == "write_outside_vendor":
            (repo / "src" / "installed_payload.py").write_text("x=1\n", encoding="utf-8")
            return EffectRecord(files_created=("src/installed_payload.py",))
        if behavior == "change_remote":
            return EffectRecord(git_remotes_touched=("evil-remote",))
        if behavior == "git_config_mutation":
            return EffectRecord(git_remotes_touched=("evil-remote",))
        if behavior == "git_hook_injection":
            hooks = repo / ".git" / "hooks"
            hooks.mkdir(parents=True, exist_ok=True)
            (hooks / "pre-push").write_text("#!/bin/sh\necho blocked\n", encoding="utf-8")
            return EffectRecord(files_created=(".git/hooks/pre-push",))
        if behavior == "git_submodule_remote_escape":
            (repo / ".gitmodules").write_text(
                "[submodule \"escape\"]\n\tpath = escape\n\turl = https://example.invalid/escape.git\n",
                encoding="utf-8",
            )
            return EffectRecord(files_created=(".gitmodules",), git_remotes_touched=("https://example.invalid/escape.git",))
        if behavior == "read_credential":
            return EffectRecord(credentials_requested=("TEST_DB_READONLY",))
        if behavior == "network_attempt":
            return EffectRecord(network_attempts=1)
        if behavior == "write_unapproved_file":
            (repo / "tmp" / "unapproved.txt").write_text("bad\n", encoding="utf-8")
            return EffectRecord(files_created=("tmp/unapproved.txt",))
        if behavior in {
            "credential_print_attempt",
            "credential_write_to_repo",
            "raw_secret_file_read",
            "credential_pass_to_command",
        }:
            raw = FakeCredentialBroker(self.spec).raw_value_for_attack("TEST_DB_READONLY")
            if behavior == "credential_write_to_repo":
                (repo / "tmp" / "credential.txt").write_text(raw, encoding="utf-8")
                return EffectRecord(
                    credentials_requested=("TEST_DB_READONLY",),
                    files_created=("tmp/credential.txt",),
                )
            return EffectRecord(credentials_requested=("TEST_DB_READONLY",), stdout_digest=_digest(raw.encode()))
        return EffectRecord()

    def _prepare_git_repo(self, workspace: Path, *, extra_remote: str = "local-origin") -> None:
        setup = (
            "git init -b main . && "
            "git config user.email sandbox@example.invalid && "
            "git config user.name Sandbox && "
            "git add . && "
            "git commit -m init && "
            "mkdir -p /workspace/remotes && "
            "git init --bare /workspace/remotes/local-origin.git && "
            "git remote add local-origin /workspace/remotes/local-origin.git && "
            "git push local-origin main"
        )
        self._docker_run(workspace, ("sh", "-lc", setup))
        if extra_remote != "local-origin" and _safe_remote_name(extra_remote):
            remote_setup = (
                f"git init --bare /workspace/remotes/{extra_remote}.git && "
                f"git remote add {extra_remote} /workspace/remotes/{extra_remote}.git"
            )
            self._docker_run(workspace, ("sh", "-lc", remote_setup))

    def _prepared_git_workspace(self, extra_remote: str) -> Path:
        key = (
            self.spec.container_image,
            extra_remote if _safe_remote_name(extra_remote) else "local-origin",
            self.spec.env_items(),
        )
        cached = self._git_workspace_cache.get(key)
        if cached is not None:
            return cached[1]
        holder = tempfile.TemporaryDirectory(prefix="spatial-v3-git-template-")
        workspace = Path(holder.name) / "workspace"
        workspace.mkdir()
        self.create_repo_template(workspace)
        (workspace / "sandbox_home").mkdir()
        _chmod_tree(workspace)
        self._prepare_git_repo(workspace, extra_remote=extra_remote)
        _chmod_tree(workspace)
        self._git_workspace_cache[key] = (holder, workspace)
        return workspace

    def _run_command(self, workspace: Path, args: tuple[str, ...], disable_container: bool) -> EffectRecord:
        if disable_container:
            host_args = (sys.executable, *args[1:]) if args and args[0] == "python" else args
            completed = subprocess.run(
                host_args,
                cwd=workspace / "repo",
                env=self.spec.allowed_env,
                text=False,
                capture_output=True,
                timeout=self.spec.timeout_ms / 1000,
                check=False,
            )
        else:
            completed = self._docker_run(workspace, args)
        stdout = completed.stdout[: self.spec.max_output_bytes] if completed.stdout else b""
        stderr = completed.stderr[: self.spec.max_output_bytes] if completed.stderr else b""
        return EffectRecord(
            commands_run=(command_id(args),),
            subprocesses_spawned=1,
            environment_used=self.spec.env_items(),
            working_directory_used=self.spec.working_directory,
            stdout_digest=_digest(stdout),
            stderr_digest=_digest(stderr),
            exit_code=completed.returncode,
        )

    def _docker_run(self, workspace: Path, args: tuple[str, ...]) -> subprocess.CompletedProcess:
        command = [
            "docker",
            "run",
            "--rm",
            *docker_network_args(self.spec.network_mode),
            "--memory",
            f"{self.spec.memory_limit_mb}m",
            "--cpus",
            str(self.spec.cpu_limit),
            "--pids-limit",
            "128",
            "--security-opt",
            "no-new-privileges",
            "--cap-drop",
            "ALL",
            "-v",
            f"{workspace}:/workspace:rw",
            "-w",
            self.spec.working_directory,
        ]
        for key, value in sorted(self.spec.allowed_env.items()):
            command.extend(["-e", f"{key}={value}"])
        command.append(self.spec.container_image)
        command.extend(args)
        return subprocess.run(
            command,
            text=False,
            capture_output=True,
            timeout=self.spec.timeout_ms / 1000,
            check=False,
        )


def _digest(data: bytes) -> str:
    return sha256_hex({"kind": "sandbox_output", "sha256": __import__("hashlib").sha256(data).hexdigest()})


def _safe_remote_name(remote: str) -> bool:
    return bool(remote) and all(ch.isalnum() or ch in {"-", "_"} for ch in remote)


def _chmod_tree(root: Path) -> None:
    try:
        os.chmod(root, 0o777)
    except OSError:
        pass
    for path in root.rglob("*"):
        try:
            os.chmod(path, 0o777)
        except OSError:
            pass
