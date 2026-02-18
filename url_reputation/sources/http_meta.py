"""Utilities to attach HTTP response metadata to provider payloads.

Built-in sources use urllib; responses expose headers as an email.message.Message.
We convert to a simple JSON-serializable shape so providers can later parse
rate-limit headers without needing network access in tests.
"""

from __future__ import annotations

from typing import Any


def headers_to_dict(headers: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    if headers is None:
        return out

    try:
        items = headers.items()
    except Exception:
        return out

    for k, v in items:
        if k is None:
            continue
        out[str(k)] = str(v)
    return out


def response_meta(response: Any) -> dict[str, Any]:
    status = getattr(response, "status", None)
    if status is None:
        try:
            status = response.getcode()
        except Exception:
            status = None

    headers = getattr(response, "headers", None)

    meta: dict[str, Any] = {}
    if status is not None:
        try:
            meta["status"] = int(status)
        except Exception:
            pass

    h = headers_to_dict(headers)
    if h:
        meta["headers"] = h
    return meta


def error_meta(err: Any) -> dict[str, Any]:
    status = getattr(err, "code", None)
    headers = getattr(err, "headers", None)

    meta: dict[str, Any] = {}
    if status is not None:
        try:
            meta["status"] = int(status)
        except Exception:
            pass

    h = headers_to_dict(headers)
    if h:
        meta["headers"] = h
    return meta
