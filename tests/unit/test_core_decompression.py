"""Unit tests for bounded decoding of compressed HTTP bodies."""

from __future__ import annotations

import gzip
import zlib

import pytest

from olympus.core.decompression import (
    DEFAULT_MAX_DECOMPRESSED_BYTES,
    DEFAULT_MAX_EXPANSION_RATIO,
    MAX_CONTENT_CODINGS,
    DecompressionError,
    DecompressionLimitExceeded,
    UnsupportedContentEncoding,
    decode_body,
    effective_output_limit,
    parse_content_encodings,
)


def _raw_deflate(payload: bytes) -> bytes:
    compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    return compressor.compress(payload) + compressor.flush()


def test_uncompressed_body_passes_through_untouched() -> None:
    assert decode_body(b"plain body", None) == b"plain body"
    assert decode_body(b"plain body", "identity") == b"plain body"


def test_decodes_gzip_and_both_deflate_flavours() -> None:
    assert decode_body(gzip.compress(b"hello"), "gzip") == b"hello"
    assert decode_body(gzip.compress(b"hello"), "x-gzip") == b"hello"
    assert decode_body(zlib.compress(b"hello"), "deflate") == b"hello"
    assert decode_body(_raw_deflate(b"hello"), "deflate") == b"hello"


def test_decodes_a_chained_coding_outermost_first() -> None:
    payload = gzip.compress(zlib.compress(b"nested"))

    assert decode_body(payload, "deflate, gzip") == b"nested"


def test_rejects_a_coding_chain_longer_than_the_limit() -> None:
    chain = ", ".join(["gzip"] * (MAX_CONTENT_CODINGS + 1))

    with pytest.raises(UnsupportedContentEncoding, match="content codings"):
        decode_body(gzip.compress(b"x"), chain)


def test_rejects_codings_olympus_cannot_bound() -> None:
    for coding in ("br", "zstd", "compress"):
        with pytest.raises(UnsupportedContentEncoding, match="unsupported content coding"):
            decode_body(b"payload", coding)


def test_parse_content_encodings_drops_identity_and_normalizes_case() -> None:
    assert parse_content_encodings("Identity, GZIP") == ("gzip",)
    assert parse_content_encodings(None) == ()
    assert parse_content_encodings("") == ()


def test_decompression_bomb_is_rejected_before_it_is_materialized() -> None:
    bomb = gzip.compress(b"\0" * (64 * 1024 * 1024))
    assert len(bomb) < 128 * 1024  # a small payload claiming an enormous body

    with pytest.raises(DecompressionLimitExceeded):
        decode_body(bomb, "gzip")


def test_expansion_ratio_bounds_a_tiny_payload() -> None:
    payload = gzip.compress(b"A" * 200_000)

    with pytest.raises(DecompressionLimitExceeded):
        decode_body(payload, "gzip", max_expansion_ratio=2.0, min_expansion_allowance=1024)


def test_absolute_ceiling_applies_even_at_a_modest_ratio() -> None:
    payload = gzip.compress(b"B" * 300_000)

    with pytest.raises(DecompressionLimitExceeded):
        decode_body(payload, "gzip", max_output_bytes=1024)


def test_realistically_compressible_page_is_still_accepted() -> None:
    body = (b"<html>" + b" " * 4096 + b"</html>") * 20

    assert decode_body(gzip.compress(body), "gzip") == body


def test_effective_limit_takes_the_stricter_of_absolute_and_ratio() -> None:
    assert (
        effective_output_limit(
            1_000, max_output_bytes=10_000, max_expansion_ratio=2.0, min_expansion_allowance=0
        )
        == 2_000
    )
    assert (
        effective_output_limit(
            1_000_000, max_output_bytes=10_000, max_expansion_ratio=2.0, min_expansion_allowance=0
        )
        == 10_000
    )
    assert (
        effective_output_limit(
            1, max_output_bytes=10_000, max_expansion_ratio=2.0, min_expansion_allowance=4_096
        )
        == 4_096
    )


def test_truncated_and_malformed_bodies_are_errors_not_partial_results() -> None:
    with pytest.raises(DecompressionError, match="truncated"):
        decode_body(gzip.compress(b"hello world")[:-4], "gzip")
    with pytest.raises(DecompressionError, match="malformed"):
        decode_body(b"not compressed at all", "gzip")


def test_limits_are_validated() -> None:
    with pytest.raises(ValueError, match="max_output_bytes"):
        decode_body(b"x", "gzip", max_output_bytes=0)
    with pytest.raises(ValueError, match="max_expansion_ratio"):
        decode_body(b"x", "gzip", max_expansion_ratio=0.5)


def test_defaults_are_bounded() -> None:
    assert 0 < DEFAULT_MAX_DECOMPRESSED_BYTES <= 100 * 1024 * 1024
    assert 1.0 <= DEFAULT_MAX_EXPANSION_RATIO <= 10_000.0
