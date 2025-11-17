# FlowSign build and benchmark helper

Use `tools/build_and_test.sh` to configure Snort3 with FlowSign, install into a
local prefix, and run the dataset replay harness.

## Prerequisites

The script expects Snort3's required dependencies to be available, most
importantly:

- `libdaq` ≥ 3.0.22. The helper will attempt to download and build the library
  automatically into `.deps/` when it is not present (requires `curl` and build
  tooling). If your network blocks downloads, pre-seed the tarball at
  `$LIBDAQ_TARBALL` (default: `.deps/libdaq-<ver>.tar.gz`) or point
  `LIBDAQ_TARBALL` at an accessible local copy to skip the fetch. You can
  provide `DAQ_INCLUDE_DIR_HINT`/`DAQ_LIBRARIES_DIR_HINT` or `LIBDAQ_PREFIX` if
  you already have a custom build.
- `cmake`, `pkg-config`, a C++17 toolchain, and supporting libraries referenced
  in `snort3/README.md`
- Python 3 with `requests` installed for dataset downloads used by
  `tools/flowsign_benchmark.py`

## Usage

From the repository root:

```bash
# configure, build, install snort3 into snort3/install, then run a dataset
./tools/build_and_test.sh unsw-nb15

# override install prefix or DAQ hints if needed
PREFIX=$HOME/snort3-install \
DAQ_INCLUDE_DIR_HINT=$HOME/libdaq/include \
DAQ_LIBRARIES_DIR_HINT=$HOME/libdaq/lib \
./tools/build_and_test.sh cic-ids2017

# use an existing libdaq tree instead of downloading
LIBDAQ_PREFIX=$HOME/libdaq-3.0.22 ./tools/build_and_test.sh nsl-kdd

# or pre-seed a tarball when outbound fetches are blocked
LIBDAQ_TARBALL=$HOME/downloads/libdaq-3.0.22.tar.gz ./tools/build_and_test.sh unsw-nb15
```

The helper surfaces missing dependencies early and exits with a non-zero status
if the Snort binary is not produced. Benchmark downloads are cached under
`data/` to avoid re-fetching dataset slices.
