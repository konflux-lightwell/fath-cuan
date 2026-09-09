from fath_cuan.gittrailers import (
    parse_adr0005_trailers,
    parse_standard_trailers,
    regex_scan,
    resolve_vulns,
)

ADR0005_MESSAGE = """Composed 2 security fixes

Lightwell-Fix: fix=LW-2026-0001, cve=CVE-2024-1234, jira=LTWL-201, status=applied_clean
Lightwell-Fix: fix=LW-2026-0002, cve=CVE-2024-5678, jira=LTWL-202, status=applied_ai
Lightwell-CT: LTWL-350
"""

NOVEL_ONLY_MESSAGE = """Add novel fix

Lightwell-Fix: fix=LW-2099-0007, jira=LTWL-900, status=applied_ai
"""


def test_parse_adr0005_prefers_cve_over_fix() -> None:
    assert parse_adr0005_trailers(ADR0005_MESSAGE) == ["CVE-2024-1234", "CVE-2024-5678"]


def test_parse_adr0005_uses_fix_when_no_cve() -> None:
    assert parse_adr0005_trailers(NOVEL_ONLY_MESSAGE) == ["LW-2099-0007"]


def test_parse_adr0005_none_present() -> None:
    assert parse_adr0005_trailers("just a normal commit message") == []


def test_parse_standard_trailers() -> None:
    text = "Fix a bug\n\nResolves: CVE-2024-1111\nFixes: LW-2099-0002\n"
    assert parse_standard_trailers(text) == ["CVE-2024-1111", "LW-2099-0002"]


def test_parse_standard_trailers_case_insensitive() -> None:
    assert parse_standard_trailers("closes: CVE-2024-2222") == ["CVE-2024-2222"]


def test_regex_scan() -> None:
    text = "mentions CVE-2024-3333 and LW-2099-0003 and CVE-2024-3333 again"
    assert regex_scan(text) == ["CVE-2024-3333", "LW-2099-0003"]


def test_resolve_tier1_cli_wins() -> None:
    r = resolve_vulns(["CVE-2024-0001"], env_value="CVE-2024-9999", git_dir="/repo")
    assert r.vulns == ["CVE-2024-0001"]
    assert r.tier == "cli"


def test_resolve_tier1_dedups() -> None:
    r = resolve_vulns(["CVE-2024-0001", "CVE-2024-0001"])
    assert r.vulns == ["CVE-2024-0001"]


def test_resolve_tier1_env() -> None:
    r = resolve_vulns([], env_value="CVE-2024-0002, CVE-2024-0003")
    assert r.vulns == ["CVE-2024-0002", "CVE-2024-0003"]
    assert r.tier == "env"


def test_resolve_tier2_adr0005() -> None:
    r = resolve_vulns(
        [],
        git_dir="/repo",
        commit_message_reader=lambda _: ADR0005_MESSAGE,
        recent_log_reader=lambda _: "",
    )
    assert r.vulns == ["CVE-2024-1234", "CVE-2024-5678"]
    assert r.tier == "adr0005-trailer"


def test_resolve_tier3_standard() -> None:
    r = resolve_vulns(
        [],
        git_dir="/repo",
        commit_message_reader=lambda _: "Fix\n\nResolves: CVE-2024-4444\n",
        recent_log_reader=lambda _: "",
    )
    assert r.vulns == ["CVE-2024-4444"]
    assert r.tier == "standard-trailer"


def test_resolve_tier4_regex() -> None:
    r = resolve_vulns(
        [],
        git_dir="/repo",
        commit_message_reader=lambda _: "no trailers here",
        recent_log_reader=lambda _: "somewhere CVE-2024-5555 on the branch",
    )
    assert r.vulns == ["CVE-2024-5555"]
    assert r.tier == "regex"


def test_resolve_clean_build() -> None:
    r = resolve_vulns(
        [],
        git_dir="/repo",
        commit_message_reader=lambda _: "chore: bump deps",
        recent_log_reader=lambda _: "nothing vuln-like",
    )
    assert r.vulns == []
    assert r.tier == "clean"


def test_resolve_no_git_no_input_is_clean() -> None:
    r = resolve_vulns([], env_value=None, git_dir=None)
    assert r.vulns == []
    assert r.tier == "clean"
