import pytest

from fath_cuan.ecosystems import (
    Coordinate,
    coordinate_from_purl,
    maven_base_version,
    maven_coordinate,
    parse_gav,
    parse_purl,
    pep503_normalize,
    pypi_base_version,
    pypi_coordinate,
)

# ---------------------------------------------------------------------------
# Maven
# ---------------------------------------------------------------------------


def test_parse_gav_valid() -> None:
    assert parse_gav("org.example:artifact:1.0.0") == ("org.example", "artifact", "1.0.0")


def test_parse_gav_invalid() -> None:
    with pytest.raises(ValueError, match="Invalid GAV format"):
        parse_gav("invalid-gav")


def test_maven_base_version_strips_rhlw() -> None:
    assert maven_base_version("2.4.8.rhlw-00001") == "2.4.8"


def test_maven_base_version_strips_rhlw_dp() -> None:
    assert maven_base_version("4.0.4.rhlw-dp-00002") == "4.0.4"


def test_maven_base_version_unchanged() -> None:
    assert maven_base_version("5.3.18") == "5.3.18"


def test_maven_coordinate() -> None:
    c = maven_coordinate("org.example:artifact:1.0.0.rhlw-00001")
    assert c.ecosystem == "maven"
    assert c.osv_ecosystem == "Maven"
    assert c.name == "org.example:artifact"
    assert c.version == "1.0.0.rhlw-00001"
    assert c.base_version == "1.0.0"
    assert c.purl == "pkg:maven/org.example/artifact@1.0.0.rhlw-00001"


def test_maven_coordinate_explicit_upstream() -> None:
    c = maven_coordinate("org.yaml:snakeyaml:1.33.0.rhlw-00001", upstream_version="1.33")
    assert c.base_version == "1.33"


# ---------------------------------------------------------------------------
# PyPI
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("coverage", "coverage"),
        ("HuggingFace_Hub", "huggingface-hub"),
        ("Django", "django"),
        ("zope.interface", "zope-interface"),
        ("a__b--c..d", "a-b-c-d"),
        ("Pillow", "pillow"),
    ],
)
def test_pep503_normalize(raw: str, expected: str) -> None:
    assert pep503_normalize(raw) == expected


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("7.6.12+rhlw.1", "7.6.12"),
        ("7.6.12+rhlw.2.n1", "7.6.12"),
        ("10.3.0", "10.3.0"),
    ],
)
def test_pypi_base_version(version: str, expected: str) -> None:
    assert pypi_base_version(version) == expected


def test_pypi_coordinate() -> None:
    c = pypi_coordinate("coverage", "7.6.12+rhlw.1")
    assert c.ecosystem == "pypi"
    assert c.osv_ecosystem == "PyPI"
    assert c.name == "coverage"
    assert c.version == "7.6.12+rhlw.1"
    assert c.base_version == "7.6.12"
    assert c.purl == "pkg:pypi/coverage@7.6.12%2Brhlw.1"


def test_pypi_coordinate_normalizes_name() -> None:
    c = pypi_coordinate("HuggingFace_Hub", "1.0.0+rhlw.1")
    assert c.name == "huggingface-hub"
    assert c.purl == "pkg:pypi/huggingface-hub@1.0.0%2Brhlw.1"


def test_pypi_coordinate_explicit_upstream() -> None:
    c = pypi_coordinate("coverage", "7.6.12+rhlw.1", upstream_version="7.6.12")
    assert c.base_version == "7.6.12"


# ---------------------------------------------------------------------------
# PURL parsing
# ---------------------------------------------------------------------------


def test_parse_purl_pypi() -> None:
    assert parse_purl("pkg:pypi/coverage@7.6.12%2Brhlw.1") == ("pypi", "coverage", "7.6.12+rhlw.1")


def test_parse_purl_maven() -> None:
    assert parse_purl("pkg:maven/org.example/artifact@1.0.0") == (
        "maven",
        "org.example/artifact",
        "1.0.0",
    )


def test_parse_purl_drops_qualifiers_and_subpath() -> None:
    assert parse_purl("pkg:pypi/coverage@7.6.12?file_name=x.whl#sub") == (
        "pypi",
        "coverage",
        "7.6.12",
    )


@pytest.mark.parametrize(
    "bad",
    [
        "coverage@1.0.0",  # no pkg: scheme
        "pkg:pypi",  # no coordinate
        "pkg:pypi/coverage",  # no @version
        "pkg:pypi/coverage@",  # empty version
    ],
)
def test_parse_purl_invalid(bad: str) -> None:
    with pytest.raises(ValueError):
        parse_purl(bad)


def test_coordinate_from_purl_pypi() -> None:
    c = coordinate_from_purl("pkg:pypi/coverage@7.6.12%2Brhlw.1", upstream_version="7.6.12")
    assert isinstance(c, Coordinate)
    assert c.ecosystem == "pypi"
    assert c.name == "coverage"
    assert c.base_version == "7.6.12"


def test_coordinate_from_purl_maven() -> None:
    c = coordinate_from_purl("pkg:maven/org.example/artifact@1.0.0.rhlw-00001")
    assert c.ecosystem == "maven"
    assert c.name == "org.example:artifact"
    assert c.base_version == "1.0.0"
    assert c.purl == "pkg:maven/org.example/artifact@1.0.0.rhlw-00001"


def test_coordinate_from_purl_ecosystem_mismatch() -> None:
    with pytest.raises(ValueError, match="does not match expected"):
        coordinate_from_purl("pkg:pypi/coverage@1.0.0", ecosystem="maven")


def test_coordinate_from_purl_unsupported() -> None:
    with pytest.raises(ValueError, match="Unsupported PURL ecosystem"):
        coordinate_from_purl("pkg:npm/left-pad@1.0.0")


# --- canonical PURL encoding (%2B for PEP 440 local version) ---


def test_pypi_purl_encodes_plus_as_2b() -> None:
    assert pypi_coordinate("coverage", "7.6.12+rhlw.1").purl == "pkg:pypi/coverage@7.6.12%2Brhlw.1"


def test_parse_purl_decodes_2b() -> None:
    assert parse_purl("pkg:pypi/coverage@7.6.12%2Brhlw.1") == ("pypi", "coverage", "7.6.12+rhlw.1")


def test_maven_purl_has_no_percent_encoding() -> None:
    # Maven versions carry no '+', so canonical encoding leaves them unchanged.
    c = maven_coordinate("org.example:artifact:1.0.0.rhlw-00001")
    assert c.purl == "pkg:maven/org.example/artifact@1.0.0.rhlw-00001"
    assert "%" not in c.purl
