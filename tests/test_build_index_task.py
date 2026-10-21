"""Verify task publication, provenance policy, and its Tekton integration contract."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from fath_cuan.tasks import build_index, registry

REFERENCE = "registry.test/team/demo@sha256:" + "a" * 64
TASK_PATH = Path(__file__).parents[1] / "tekton/task/attach-build-index/0.2/attach-build-index.yaml"


@pytest.fixture
def source(tmp_path, monkeypatch):
    """Create real source history without relying on a developer's Git configuration."""
    monkeypatch.delenv("VULN_IDS", raising=False)
    repo = tmp_path / "source"
    subprocess.run(["git", "init", str(repo)], check=True, capture_output=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.org",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--allow-empty",
            "-m",
            "Fix package\n\nLightwell-Fix: cve=CVE-2025-12345",
        ],
        check=True,
        capture_output=True,
    )
    return repo


@pytest.fixture
def fake_oras(tmp_path, monkeypatch):
    """Run an executable recording the actual payload and private auth passed to ORAS."""
    executable = tmp_path / "bin" / "oras"
    executable.parent.mkdir()
    executable.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, pathlib, sys\n"
        "auth = pathlib.Path(sys.argv[sys.argv.index('--registry-config') + 1])\n"
        "record = {'args': sys.argv[1:], 'auth': json.loads(auth.read_text()), "
        "'mode': auth.stat().st_mode & 0o777, 'auth_path': str(auth), "
        "'payload': pathlib.Path('build-index.json').read_text()}\n"
        "pathlib.Path(os.environ['ORAS_RECORD']).write_text(json.dumps(record))\n"
    )
    executable.chmod(0o755)
    record = tmp_path / "oras-record.json"
    monkeypatch.setenv("PATH", str(executable.parent) + os.pathsep + os.environ["PATH"])
    monkeypatch.setenv("ORAS_RECORD", str(record))
    return record


def cli_arguments(tmp_path, source, build_type="Backport", computed="1.0+rhlw.2"):
    """Provide the same local paths and value syntax as the Tekton task."""
    return [
        "--package=Demo_Name",
        "--version=1.0",
        f"--computed-version={computed}",
        f"--build-type={build_type}",
        f"--source-dir={source}",
        f"--image-ref={REFERENCE}",
        f"--workdir={tmp_path / 'work'}",
        f"--results-dir={tmp_path / 'results'}",
    ]


@pytest.mark.parametrize(
    ("build_type", "computed", "counts"),
    [
        ("Backport", "1.0+rhlw.2", (2, 0)),
        ("Novel", "1.0+rhlw.2.n.3", (2, 3)),
        ("Validated", "1.0", (0, 0)),
    ],
)
@pytest.mark.parametrize("manifest_mode", ["absent", "artifact", "local"])
def test_cli_publishes_exact_bytes_and_results(
    tmp_path,
    source,
    fake_oras,
    build_type,
    computed,
    counts,
    manifest_mode,
):
    """Real Git and subprocess execution feed validated bytes to ORAS before results."""
    if build_type == "Validated":
        subprocess.run(
            [
                "git",
                "-C",
                str(source),
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.org",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "--amend",
                "--allow-empty",
                "-m",
                "Validated upstream",
            ],
            check=True,
            capture_output=True,
        )
    arguments = cli_arguments(tmp_path, source, build_type, computed)
    auth = tmp_path / "auth.json"
    original = {
        "auths": {
            "registry.test/team": {"auth": "scoped-secret"},
            "registry.test": {"auth": "broad-secret"},
        }
    }
    auth.write_text(json.dumps(original))
    arguments.append(f"--auth-file={auth}")
    with_manifest = manifest_mode != "absent"
    manifest = tmp_path / "manifest.json"
    # An empty task parameter must ignore even a stale, malformed file.
    manifest.write_text("not JSON")
    arguments.append(f"--manifest-path={manifest}")
    if manifest_mode != "local":
        artifact = "registry.test/manifest@sha256:" + "b" * 64 if with_manifest else ""
        arguments.append(f"--manifest-artifact={artifact}")
    if with_manifest:
        manifest.write_text(
            json.dumps(
                {
                    "produced": [
                        {"name": "Demo_Name", "version": computed},
                        {"name": "Companion_Name", "version": "2.0+rhlw.1"},
                    ],
                    "cached": [
                        {"name": "companion-name", "version": "2.0+rhlw.1"},
                        {"name": "dependency", "version": "3.0"},
                    ],
                }
            )
        )

    result = CliRunner().invoke(build_index.main, arguments)
    assert result.exit_code == 0, result.output
    record = json.loads(fake_oras.read_text())
    document = json.loads(record["payload"])
    assert document["primaryPurl"].startswith("pkg:pypi/demo-name@")
    assert (document["version"]["b"], document["version"]["n"]) == counts
    assert document["vulns"] == ([] if build_type == "Validated" else ["CVE-2025-12345"])
    assert len(document["purls"]) == (2 if with_manifest else 1)
    if with_manifest:
        assert document["extraPurls"] == ["pkg:pypi/dependency@3.0"]
    assert record["args"][-1] == f"build-index.json:{registry.MEDIA_TYPE}"
    assert record["auth"] == {"auths": {"registry.test": {"auth": "scoped-secret"}}}
    assert record["mode"] == 0o600
    assert not Path(record["auth_path"]).exists()
    assert json.loads(auth.read_text()) == original
    assert (tmp_path / "results/BUILD_INDEX_ATTACHED_REF").read_text() == REFERENCE
    assert (tmp_path / "results/BUILD_INDEX_DIGEST").read_text() == (
        "sha256:" + hashlib.sha256(record["payload"].encode()).hexdigest()
    )


@pytest.mark.parametrize(
    "failure",
    ["manifest", "artifact-missing", "artifact-malformed", "history", "version", "attachment"],
)
def test_failure_emits_no_success_results(tmp_path, source, fake_oras, monkeypatch, failure):
    """Bad evidence and failed publication must not report successful task results."""
    arguments = cli_arguments(tmp_path, source)
    if failure == "manifest":
        arguments.append(f"--manifest-path={tmp_path / 'missing.json'}")
    elif failure.startswith("artifact-"):
        arguments.append("--manifest-artifact=registry.test/manifest@sha256:" + "b" * 64)
        # Exercise the default restored path when --manifest-path is omitted.
        if failure == "artifact-malformed":
            manifest = tmp_path / "work/manifest/build-manifest.json"
            manifest.parent.mkdir(parents=True)
            manifest.write_text("not JSON")
    elif failure == "history":
        subprocess.run(
            [
                "git",
                "-C",
                str(source),
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.org",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "--allow-empty",
                "-m",
                "No trailers",
            ],
            check=True,
            capture_output=True,
        )
    elif failure == "version":
        arguments[2] = "--computed-version=2.0+rhlw.2"
    else:

        def fail(*args, **kwargs):
            raise ValueError("Registry unavailable")

        monkeypatch.setattr(build_index, "attach_index", fail)
    result = CliRunner().invoke(build_index.main, arguments)
    assert result.exit_code == 1
    assert not (tmp_path / "results").exists()
    assert not fake_oras.exists()


@pytest.mark.parametrize(
    ("build_type", "computed"),
    [
        ("Unknown", "1.0"),
        ("Validated", "1.0+rhlw.1"),
        ("Backport", "1.0+rhlw.1.n.2"),
        ("Novel", "2.0+rhlw.1"),
        ("Novel", "invalid"),
    ],
)
def test_rejects_versions_inconsistent_with_policy(build_type, computed):
    with pytest.raises(ValueError):
        build_index.version_counts("1.0", computed, build_type)


@pytest.mark.parametrize(
    "manifest",
    [[], {"produced": {}}, {"cached": [1]}, {"produced": [{"name": "demo", "version": 1}]}],
)
def test_invalid_manifest_fails_closed(tmp_path, manifest):
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError):
        build_index.manifest_purls(path, "primary")


def test_duplicate_json_keys_are_rejected(tmp_path):
    path = tmp_path / "manifest.json"
    path.write_text('{"produced": [], "produced": []}')
    with pytest.raises(ValueError, match="Duplicate"):
        build_index.manifest_purls(path, "primary")


def test_oras_failure_retries_and_removes_credentials(tmp_path, monkeypatch):
    payload = tmp_path / "build-index.json"
    payload.write_text("{}")
    calls = []

    def fail(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 1)

    monkeypatch.setattr(registry.subprocess, "run", fail)
    monkeypatch.setattr(registry.time, "sleep", lambda delay: None)
    with pytest.raises(ValueError, match="attachment failed"):
        registry.attach_index(REFERENCE, payload)
    assert len(calls) == 3
    assert all(not Path(call[call.index("--registry-config") + 1]).exists() for call in calls)


def test_validated_publishes_without_git_history(tmp_path, fake_oras, monkeypatch):
    """Validated content creates its artifact without vulnerability evidence.

    A source tree without .git and a stray VULN_IDS value must not block a
    Validated build or leak an ID into its index: the validated release
    stream requires zero vulnerabilities of any kind.
    """
    plain = tmp_path / "plain-source"
    plain.mkdir()
    monkeypatch.setenv("VULN_IDS", "CVE-2025-99999")
    arguments = cli_arguments(tmp_path, plain, build_type="Validated", computed="1.0")
    result = CliRunner().invoke(build_index.main, arguments)
    assert result.exit_code == 0, result.output
    document = json.loads(json.loads(fake_oras.read_text())["payload"])
    assert document["vulns"] == []
    assert (tmp_path / "results/BUILD_INDEX_DIGEST").exists()


@pytest.mark.parametrize("manifest_uri", ["", "registry.test/manifest@sha256:abc"])
def test_tekton_restores_artifacts_then_dispatches_one_cli(
    tmp_path,
    source,
    monkeypatch,
    manifest_uri,
):
    """One unconditional CLI step selects the manifest after optional restoration."""
    task = yaml.safe_load(TASK_PATH.read_text())["spec"]
    parameters = {item["name"]: item.get("default", "") for item in task["params"]}
    parameters.update(
        {
            "PACKAGE": "demo",
            "VERSION": "1.0",
            "COMPUTED_VERSION": "1.0",
            "BUILD_TYPE": "Validated",
            "IMAGE_REF": REFERENCE,
            "MANIFEST_ARTIFACT": manifest_uri,
            "SOURCE_ARTIFACT": "source-uri",
        }
    )
    active = []
    cli_steps = [step for step in task["steps"] if "command" in step]
    assert len(cli_steps) == 1
    assert cli_steps[0]["name"] == "create-and-attach"
    assert "when" not in cli_steps[0]
    for step in task["steps"]:
        assert "script" not in step
        selected = True
        for condition in step.get("when", []):
            value = parameters[condition["input"][9:-1]]
            matches = value in condition["values"]
            selected &= matches if condition["operator"] == "in" else not matches
        if selected:
            active.append(step)
    restores = [step for step in active if "command" not in step]
    assert len(restores) == (2 if manifest_uri else 1)
    assert all(
        step["image"].startswith("quay.io/konflux-ci/build-trusted-artifacts:") for step in restores
    )
    assert all(step["args"][0] == "use" for step in restores)
    commands = [step for step in active if "command" in step]
    assert len(commands) == 1
    assert active[-1] == commands[0]
    assert commands[0]["command"] == ["fath-cuan-attach-build-index"]
    arguments = [
        re.sub(r"\$\(params\.([^)]+)\)", lambda m: parameters[m[1]], value).replace(
            "$(workspaces.registry-auth.path)", str(tmp_path)
        )
        for value in commands[0]["args"]
    ]
    captured = {}

    def capture(**kwargs):
        captured.update(kwargs)
        return tmp_path / "build-index.json"

    monkeypatch.setattr(build_index, "run", capture)
    result = CliRunner().invoke(build_index.main, arguments)
    assert result.exit_code == 0, result.output
    assert bool(captured["manifest_path"]) is bool(manifest_uri)
    assert set(item["name"] for item in task["results"]) == {
        "BUILD_INDEX_ATTACHED_REF",
        "BUILD_INDEX_DIGEST",
    }
