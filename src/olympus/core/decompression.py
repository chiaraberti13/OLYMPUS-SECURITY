"""Bounded decoding of compressed HTTP response bodies.

A compressed response is an amplifier: a few kilobytes on the wire can expand
into gigabytes in memory (the "zip bomb" / decompression bomb pattern). The
transfer-size cap enforced while streaming therefore says nothing about how
much memory the decoded body needs.

Decoding here is deliberately bounded twice:

* an **absolute** ceiling on the decoded size, and
* an **expansion ratio** relative to the compressed payload, so a small
  hostile body cannot claim the whole absolute budget.

Only the codecs the standard library can decode incrementally are accepted.
Anything else (``br``, ``zstd``, ``compress``) is refused rather than silently
handed back as opaque bytes that later decode into mojibake.
"""

from __future__ import annotations

import zlib

#: Content codings Olympus decodes. ``identity`` means "no coding applied".
SUPPORTED_ENCODINGS = frozenset({"identity", "gzip", "x-gzip", "deflate", "x-deflate"})

#: Absolute ceiling on a decoded body (8 MiB).
DEFAULT_MAX_DECOMPRESSED_BYTES = 8 * 1024 * 1024

#: Decoded output may not exceed this multiple of the compressed payload.
#: Real pages compress ~4-10x; 100x leaves honest headroom while still capping
#: amplification well below what a decompression bomb needs.
DEFAULT_MAX_EXPANSION_RATIO = 100.0

#: Ratio floor: small payloads always get this much decoded budget, because a
#: valid gzip stream carries ~20 bytes of framing and a strict ratio applied to
#: it would reject legitimate short responses.
DEFAULT_MIN_EXPANSION_ALLOWANCE = 1024 * 1024

#: Decode in slices so the limit is enforced *before* memory is committed.
_DECODE_CHUNK_BYTES = 64 * 1024

#: Bound the number of chained codings; each one multiplies the attack budget.
MAX_CONTENT_CODINGS = 2

_GZIP_WINDOW = 16 + zlib.MAX_WBITS
_ZLIB_WINDOW = zlib.MAX_WBITS
_RAW_DEFLATE_WINDOW = -zlib.MAX_WBITS


class DecompressionError(RuntimeError):
    """Raised when a response body cannot be safely decoded."""


class UnsupportedContentEncoding(DecompressionError):
    """Raised for a content coding Olympus refuses to decode."""


class DecompressionLimitExceeded(DecompressionError):
    """Raised when decoded output exceeds the absolute or ratio bound."""


def parse_content_encodings(header_value: str | None) -> tuple[str, ...]:
    """Return the applied content codings, outermost first, minus ``identity``.

    Raises :class:`UnsupportedContentEncoding` for any coding this module
    cannot decode, and for a chain longer than :data:`MAX_CONTENT_CODINGS`.
    """
    if header_value is None:
        return ()
    codings = [item.strip().lower() for item in header_value.split(",") if item.strip()]
    for coding in codings:
        if coding not in SUPPORTED_ENCODINGS:
            raise UnsupportedContentEncoding(f"unsupported content coding: {coding!r}")
    applied = tuple(coding for coding in codings if coding != "identity")
    if len(applied) > MAX_CONTENT_CODINGS:
        raise UnsupportedContentEncoding(
            f"refusing a chain of {len(applied)} content codings (limit {MAX_CONTENT_CODINGS})"
        )
    return applied


def effective_output_limit(
    compressed_size: int,
    *,
    max_output_bytes: int,
    max_expansion_ratio: float,
    min_expansion_allowance: int = DEFAULT_MIN_EXPANSION_ALLOWANCE,
) -> int:
    """Return the decoded-size budget for a payload of ``compressed_size`` bytes."""
    ratio_budget = max(int(compressed_size * max_expansion_ratio), min_expansion_allowance)
    return min(max_output_bytes, ratio_budget)


def _decode_one(payload: bytes, coding: str, limit: int) -> bytes:
    windows: tuple[int, ...]
    if coding in {"gzip", "x-gzip"}:
        windows = (_GZIP_WINDOW,)
    else:  # deflate: RFC 9110 says zlib, but servers ship raw deflate too.
        windows = (_ZLIB_WINDOW, _RAW_DEFLATE_WINDOW)

    last_error: zlib.error | None = None
    for window in windows:
        decompressor = zlib.decompressobj(window)
        decoded = bytearray()
        try:
            offset = 0
            while True:
                pending = decompressor.unconsumed_tail
                if not pending and offset < len(payload):
                    pending = payload[offset : offset + _DECODE_CHUNK_BYTES]
                    offset += len(pending)
                elif not pending:
                    break
                # ``max_length`` keeps one slice from allocating past the budget.
                decoded.extend(decompressor.decompress(pending, _DECODE_CHUNK_BYTES))
                if len(decoded) > limit:
                    raise DecompressionLimitExceeded(
                        f"decoded body exceeds the {limit} byte budget for {coding!r}"
                    )
            decoded.extend(decompressor.flush())
        except zlib.error as exc:
            last_error = exc
            continue
        if len(decoded) > limit:
            raise DecompressionLimitExceeded(
                f"decoded body exceeds the {limit} byte budget for {coding!r}"
            )
        if not decompressor.eof:
            raise DecompressionError(f"truncated {coding} body")
        return bytes(decoded)
    raise DecompressionError(f"malformed {coding} body: {last_error}")


def decode_body(
    payload: bytes,
    header_value: str | None,
    *,
    max_output_bytes: int = DEFAULT_MAX_DECOMPRESSED_BYTES,
    max_expansion_ratio: float = DEFAULT_MAX_EXPANSION_RATIO,
    min_expansion_allowance: int = DEFAULT_MIN_EXPANSION_ALLOWANCE,
) -> bytes:
    """Decode ``payload`` per its ``Content-Encoding``, under hard size bounds."""
    if max_output_bytes < 1:
        raise ValueError("max_output_bytes must be positive")
    if max_expansion_ratio < 1.0:
        raise ValueError("max_expansion_ratio must be at least 1.0")
    codings = parse_content_encodings(header_value)
    if not codings:
        return payload
    limit = effective_output_limit(
        len(payload),
        max_output_bytes=max_output_bytes,
        max_expansion_ratio=max_expansion_ratio,
        min_expansion_allowance=min_expansion_allowance,
    )
    decoded = payload
    # Content-Encoding lists codings in the order they were applied, so undo
    # them from the outermost (last listed) inwards.
    for coding in reversed(codings):
        decoded = _decode_one(decoded, coding, limit)
    return decoded
