"""Shared helpers for probes."""

from __future__ import annotations

import logging
from typing import Callable, Iterable, TypeVar

from botocore.exceptions import ClientError, EndpointConnectionError

log = logging.getLogger(__name__)

T = TypeVar("T")


# A reasonable default set of regions to probe. Override via CLI if needed.
DEFAULT_REGIONS = [
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "eu-west-1",
    "eu-west-2",
    "eu-central-1",
    "ap-northeast-1",
    "ap-southeast-1",
    "ap-southeast-2",
]


def safe(fn: Callable[[], T], *, what: str, default: T) -> T:
    """Run fn() and swallow common AWS errors into a default value with a log line."""
    try:
        return fn()
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "?")
        log.warning("%s skipped (%s): %s", what, code, e)
        return default
    except EndpointConnectionError as e:
        log.warning("%s skipped (no endpoint): %s", what, e)
        return default
    except Exception as e:  # noqa: BLE001
        log.warning("%s skipped (%s)", what, e)
        return default


def for_regions(regions: Iterable[str], fn: Callable[[str], T]) -> dict[str, T]:
    """Call fn(region) for each region, swallowing errors per-region."""
    out: dict[str, T] = {}
    for r in regions:
        try:
            out[r] = fn(r)
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "?")
            log.warning("region %s skipped (%s): %s", r, code, e)
        except EndpointConnectionError:
            # Service not available in this region — silent.
            continue
        except Exception as e:  # noqa: BLE001
            log.warning("region %s skipped (%s)", r, e)
    return out
