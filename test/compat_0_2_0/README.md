# Sketches of version 0.2.0

The example sketches exactly as version 0.2.0 shipped them (commit
`16a2b40`). `test/build_firmware.sh` compiles them, unchanged, against the
current library: a sketch written for 0.2.0 must keep compiling.

Do not edit them. They are not examples of current practice: they create
64 KB tasks that are no longer needed, wipe secrets with `memset()`, and
`mldsa_demo_arduino` calls the C API with the argument lists that
`src/mldsa_compat.h` keeps working. `mldsa_test_vectors` carries the wrong
expected value that 0.2.0 had, so it reports one failure when run.
