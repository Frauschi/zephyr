#!/usr/bin/env python3
# Copyright (c) 2026 wolfSSL Inc.
# SPDX-License-Identifier: Apache-2.0
"""Check that prj_wolfssl.conf stays in sync with prj.conf.

prj_wolfssl.conf is a standalone CONF_FILE for the net.socket.tls.wolfssl
scenario (not an overlay), so the backend-neutral options it duplicates
from prj.conf can silently drift when prj.conf changes upstream. This
script fails when:

 - a backend-neutral option from prj.conf is missing from, or has a
   different value in, prj_wolfssl.conf, or
 - prj_wolfssl.conf contains an option that is neither backend-neutral
   (matching prj.conf) nor an expected wolfSSL/POSIX addition.

Run it from anywhere:  python3 tests/net/socket/tls/check_conf_sync.py
"""

import re
import sys
from pathlib import Path

HERE = Path(__file__).parent

# Options that only exist in prj.conf (mbedTLS backend specifics).
PRJ_ONLY = re.compile(r"^CONFIG_MBEDTLS")

# Options that only exist in prj_wolfssl.conf (wolfSSL backend specifics).
WOLFSSL_ONLY = re.compile(
    r"^CONFIG_(WOLFSSL|POSIX_)"
    r"|^CONFIG_MBEDTLS=n$"
    r"|^CONFIG_COMMON_LIBC_MALLOC_ARENA_SIZE="
)


def read_options(path):
    opts = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition("=")
        opts[key] = value
    return opts


def main():
    prj = read_options(HERE / "prj.conf")
    wolf = read_options(HERE / "prj_wolfssl.conf")
    errors = []

    for key, value in prj.items():
        if PRJ_ONLY.match(f"{key}={value}"):
            continue
        if key not in wolf:
            errors.append(f"missing from prj_wolfssl.conf: {key}={value}")
        elif wolf[key] != value and not WOLFSSL_ONLY.match(f"{key}={wolf[key]}"):
            errors.append(
                f"value drift for {key}: prj.conf={value} "
                f"prj_wolfssl.conf={wolf[key]}"
            )

    for key, value in wolf.items():
        entry = f"{key}={value}"
        if WOLFSSL_ONLY.match(entry):
            continue
        if key not in prj:
            errors.append(f"unexpected in prj_wolfssl.conf: {entry}")

    if errors:
        print("prj.conf / prj_wolfssl.conf are out of sync:")
        for err in errors:
            print(f"  - {err}")
        return 1

    print("prj.conf and prj_wolfssl.conf are in sync")
    return 0


if __name__ == "__main__":
    sys.exit(main())
