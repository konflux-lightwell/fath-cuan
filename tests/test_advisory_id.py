"""Advisory IDs derived by fath-cuan must match slan-cuan's (LWLP-5917)."""

from datetime import UTC, datetime

import pytest

from fath_cuan.advisory_id import ADVISORY_ID_RE, derive_advisory_id

_BUILT = datetime(2026, 11, 13, 18, 59, 33, tzinfo=UTC)


@pytest.mark.parametrize(
    ("name", "version", "expected"),
    [
        # IDs slan-cuan derived and published for these builds.
        ("ch.qos.logback:logback-classic", "1.5.9.rhlw-00034", "RHLW-2026-33400e52ea4f277c"),
        ("ch.qos.logback:logback-classic", "1.5.38.rhlw-00006", "RHLW-2026-b7f60b9979a4b5a4"),
        (
            "io.netty:netty-codec-http3",
            "4.2.13.Final-rhlw-00014-n-00003",
            "RHLW-2026-25a7ec216235384e",
        ),
    ],
)
def test_matches_published_ids(name: str, version: str, expected: str) -> None:
    assert derive_advisory_id("Maven", name, version, _BUILT) == expected


def test_year_and_format() -> None:
    advisory_id = derive_advisory_id(
        "Maven", "ch.qos.logback:logback-core", "1.5.9.rhlw-00034", datetime(2027, 1, 1)
    )
    assert advisory_id.startswith("RHLW-2027-")
    assert ADVISORY_ID_RE.match(advisory_id)


def test_requires_name_and_version() -> None:
    with pytest.raises(ValueError):
        derive_advisory_id("Maven", "ch.qos.logback:logback-core", "")
