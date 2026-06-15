"""Zeroization helpers (software-level, testable locally).

A real enclave zeroizes physical memory; locally we clear the references the service
holds so the seed, full puzzle, and pieces are dropped on destroy/failure. The
redaction scanner separately verifies no secret reaches any artifact.
"""

from __future__ import annotations


def zeroize_mapping(d: dict) -> None:
    for key in list(d):
        d[key] = None
    d.clear()


def zeroize_bytearray(buf: bytearray) -> None:
    for i in range(len(buf)):
        buf[i] = 0
