#!/usr/bin/env bash
set -euo pipefail

# Orchestrates Snort3/FlowSign build and dataset benchmarks.
# Exits early with helpful messaging when required dependencies (e.g., libdaq)
# are unavailable so that CI environments fail loudly.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SNORT_DIR="$ROOT/snort3"
BUILD_DIR="${BUILD_DIR:-$SNORT_DIR/build}"
PREFIX="${PREFIX:-$SNORT_DIR/install}"
SNORT_BIN="${SNORT_BIN:-$PREFIX/bin/snort}"
CONFIG_PATH="${CONFIG_PATH:-$SNORT_DIR/etc/snort.lua}"

if ! command -v cmake >/dev/null 2>&1; then
  echo "cmake is required to configure and build Snort" >&2
  exit 1
fi

if ! command -v pkg-config >/dev/null 2>&1; then
  echo "pkg-config is required to locate libdaq and other dependencies" >&2
  exit 1
fi

LIBDAQ_VERSION="${LIBDAQ_VERSION:-3.0.22}"
DEPS_DIR="$ROOT/.deps"
LIBDAQ_PREFIX="${LIBDAQ_PREFIX:-$DEPS_DIR/libdaq-install}"
LIBDAQ_TARBALL="${LIBDAQ_TARBALL:-$DEPS_DIR/libdaq-$LIBDAQ_VERSION.tar.gz}"
LIBDAQ_SOURCE_DIR="${LIBDAQ_SOURCE_DIR:-$DEPS_DIR/libdaq-$LIBDAQ_VERSION}"
BOOTSTRAP_LIBDAQ="${BOOTSTRAP_LIBDAQ:-1}"

if [[ "$BOOTSTRAP_LIBDAQ" = "1" ]] && ! command -v curl >/dev/null 2>&1; then
  echo "curl is required to download libdaq automatically; set BOOTSTRAP_LIBDAQ=0 or preseed LIBDAQ_TARBALL to disable." >&2
  exit 1
fi

ensure_libdaq() {
  if pkg-config --exists "libdaq >= ${LIBDAQ_VERSION}"; then
    return
  fi

  if [[ -f "$LIBDAQ_PREFIX/lib/pkgconfig/libdaq.pc" ]]; then
    export PKG_CONFIG_PATH="$LIBDAQ_PREFIX/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
    return
  fi

  if [[ "$BOOTSTRAP_LIBDAQ" != "1" ]]; then
    echo "libdaq >= ${LIBDAQ_VERSION} is missing. Install it from https://github.com/snort3/libdaq" >&2
    echo "or set DAQ_INCLUDE_DIR_HINT/DAQ_LIBRARIES_DIR_HINT/LIBDAQ_PREFIX to point at a local build." >&2
    exit 2
  fi

  mkdir -p "$DEPS_DIR"
  if [[ ! -f "$LIBDAQ_TARBALL" ]]; then
    echo "Downloading libdaq v${LIBDAQ_VERSION} to $LIBDAQ_TARBALL" >&2
    if ! curl -L -o "$LIBDAQ_TARBALL" "https://github.com/snort3/libdaq/archive/refs/tags/v${LIBDAQ_VERSION}.tar.gz"; then
      cat >&2 <<'EOF'
libdaq download failed. If your network blocks outbound fetches, place a pre-downloaded
tarball at the path pointed to by $LIBDAQ_TARBALL (or set LIBDAQ_TARBALL to an accessible
location) and rerun this script. You can also disable bootstrap with BOOTSTRAP_LIBDAQ=0
when providing DAQ_INCLUDE_DIR_HINT/DAQ_LIBRARIES_DIR_HINT for an existing installation.
EOF
      exit 2
    fi
  fi

  if [[ ! -d "$LIBDAQ_SOURCE_DIR" ]]; then
    tar -xzf "$LIBDAQ_TARBALL" -C "$DEPS_DIR"
  fi

  echo "Bootstrapping libdaq v${LIBDAQ_VERSION} into $LIBDAQ_PREFIX" >&2
  pushd "$LIBDAQ_SOURCE_DIR" >/dev/null
  ./bootstrap && ./configure --prefix="$LIBDAQ_PREFIX"
  make -j"$(nproc)"
  make install
  popd >/dev/null

  export PKG_CONFIG_PATH="$LIBDAQ_PREFIX/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
}

ensure_libdaq

CONFIG_OPTS=("--prefix=$PREFIX")
if [[ -n "${DAQ_INCLUDE_DIR_HINT:-}" ]]; then
  CONFIG_OPTS+=("--with-daq-includes=${DAQ_INCLUDE_DIR_HINT}")
fi
if [[ -n "${DAQ_LIBRARIES_DIR_HINT:-}" ]]; then
  CONFIG_OPTS+=("--with-daq-libraries=${DAQ_LIBRARIES_DIR_HINT}")
fi
if [[ -f "$LIBDAQ_PREFIX/lib/pkgconfig/libdaq.pc" ]]; then
  CONFIG_OPTS+=("--with-daq-includes=${LIBDAQ_PREFIX}/include" "--with-daq-libraries=${LIBDAQ_PREFIX}/lib")
fi

pushd "$SNORT_DIR" >/dev/null
./configure_cmake.sh "${CONFIG_OPTS[@]}"
cmake --build "$BUILD_DIR" --target install -j"$(nproc)"
popd >/dev/null

if [[ ! -x "$SNORT_BIN" ]]; then
  echo "Snort binary was not found at $SNORT_BIN" >&2
  exit 3
fi

python3 "$ROOT/tools/flowsign_benchmark.py" --snort-bin "$SNORT_BIN" --config "$CONFIG_PATH" "$@"
