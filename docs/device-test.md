# On-device test procedure

Run this on a real board before each release. The host tests and the firmware
builds in CI do not replace it: they cannot show that the code runs within
the stack, timing and watchdog limits of a device.

## What you need

- An ESP32 board. Use one Xtensa board (ESP32, ESP32-S2 or ESP32-S3) and, if
  you have one, one RISC-V board (ESP32-C3 or ESP32-C6).
- PlatformIO (`pip install platformio`).

## Steps

1. Note the board, its SoC, the Arduino-ESP32 core version and the commit
   under test.

2. Flash the three-variant regression firmware and read its report. Use the
   environment that matches your board, or add one to
   `test/build_variants/platformio.ini`.

   ```sh
   pio run -d test/build_variants -e lilygo-t-display-s3 -t upload
   pio device monitor -d test/build_variants
   ```

   Expected: one `[PASS]` line for each of ML-DSA-44, ML-DSA-65 and
   ML-DSA-87, one for the two concurrent tasks, then `ALL VARIANTS PASSED`.
   Note the `stack:` and `heap:` lines.

3. Flash the test vector example and read its report.

   ```sh
   pio ci examples/mldsa_test_vectors --lib src --board lilygo-t-display-s3 \
     --build-dir /tmp/mldsa_test_vectors --keep-build-dir
   pio run -d /tmp/mldsa_test_vectors -t upload
   pio device monitor -d /tmp/mldsa_test_vectors
   ```

   Expected: one line per parameter set with `0 failed`, then
   `Results: 291 passed, 0 failed -- ALL TESTS PASSED`. The number of checks
   changes if `acvp_vectors.h` is regenerated with other options.

4. Run the NVS key storage tests. They write to the NVS partition of the
   board, in namespaces of their own.

   ```sh
   pio run -d test/nvs_device -e functional -t upload
   pio device monitor -d test/nvs_device
   ```

   Expected: every line `[PASS]`, then `NVS DEVICE TESTS PASSED`. The test
   needs about 460 free NVS entries; on a board whose `nvs` partition is
   in use by other firmware it says so and stops.

   ```sh
   pio run -d test/nvs_device -e powercut -t upload
   python3 test/nvs_device/powercut.py /dev/ttyACM0 100
   ```

   The script resets the board 100 times at random moments while it replaces
   keys. Expected: `POWER-CUT TEST PASSED`, with every boot reporting both
   identities `VALID`. Flash another firmware afterwards: this one keeps
   writing to NVS for as long as it runs.

5. Keep the serial logs with the release notes.

## Things that go wrong on the bench

- **Text missing from the serial output.** Boards that print over native USB
  (ESP32-S3, ESP32-C3) drop text printed in a burst right after reset. Both
  firmwares repeat their final verdict every few seconds for that reason;
  trust the verdict line, not the lines above it.
- **Task watchdog reset.** A task that computes for more than about five
  seconds without yielding trips the FreeRTOS task watchdog. The test sketch
  yields between cases; keep that if you change it.
- **Wrong stack readings.** On Arduino-ESP32 2.0.x,
  `uxTaskGetStackHighWaterMark()` is truncated to 16 bits, so it wraps for a
  task with more than 64 KB of stack free. Measure large stacks by filling a
  static stack buffer and scanning it.
