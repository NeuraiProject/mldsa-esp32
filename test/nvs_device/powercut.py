#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Reset the board at random moments while it replaces keys in NVS.

The firmware (environment "powercut") saves an ML-DSA-44 seed record and an
ML-DSA-87 secret-key record over and over. On every boot, before it saves
anything, it tries to load both and reports what it found. This script
resets the board through the USB serial reset line, which cuts whatever
write is in progress, and checks that every boot finds a whole identity.

    python3 test/nvs_device/powercut.py PORT [RESETS]

Exit status 0 if no boot reported a lost or broken identity.
"""
import random
import re
import sys
import time

import serial

port = sys.argv[1]
resets = int(sys.argv[2]) if len(sys.argv) > 2 else 100
LINE = re.compile(rb"PC up=(\d+) ms seed44=(\w+) sk87=(\w+) saves=(\d+)")


def open_port(deadline):
    while time.time() < deadline:
        try:
            s = serial.Serial()
            s.port, s.baudrate, s.timeout = port, 115200, 0.02
            s.dtr = s.rts = False
            s.open()
            return s
        except (serial.SerialException, OSError):
            time.sleep(0.05)
    sys.exit("could not open " + port)


def reset(s):
    s.rts = True
    time.sleep(0.05)
    s.rts = False


def read_status(s, max_uptime_ms, timeout=15):
    """Next status line of a boot younger than max_uptime_ms; reopens the port if needed."""
    deadline = time.time() + timeout
    buf = b""
    while time.time() < deadline:
        try:
            buf += s.read(4096)
        except (serial.SerialException, OSError):
            try:
                s.close()
            except Exception:
                pass
            s = open_port(deadline)
            buf = b""
            continue
        for m in LINE.finditer(buf):
            if int(m.group(1)) <= max_uptime_ms:
                return s, m
        buf = buf[-200:]
    return s, None


counts = {}
bad = 0
total_saves = 0
s = open_port(time.time() + 10)
reset(s)
for i in range(resets + 1):
    s, m = read_status(s, max_uptime_ms=3000)
    if m is None:
        print(f"boot {i}: no status line")
        bad += 1
    else:
        seed44, sk87 = m.group(2).decode(), m.group(3).decode()
        counts[(seed44, sk87)] = counts.get((seed44, sk87), 0) + 1
        # NONE is fine only before the first save ever completed.
        if any(v in ("LOST", "BROKEN") for v in (seed44, sk87)) or (i > 3 and "NONE" in (seed44, sk87)):
            print(f"boot {i}: seed44={seed44} sk87={sk87}")
            bad += 1
    if i == resets:
        break
    # Let it run a random time, read how far it got, and cut it.
    run = random.uniform(0.15, 1.2)
    time.sleep(run)
    try:
        tail = s.read(65536)
        found = LINE.findall(tail)
        if found:
            total_saves += int(found[-1][3])
    except (serial.SerialException, OSError):
        pass
    reset(s)

print(f"{resets} resets, about {total_saves} saves interrupted or completed in between")
for (seed44, sk87), n in sorted(counts.items()):
    print(f"  {n:4d} boots found seed44={seed44} sk87={sk87}")
print("POWER-CUT TEST PASSED" if bad == 0 else f"POWER-CUT TEST FAILED ({bad} bad boots)")
sys.exit(0 if bad == 0 else 1)
