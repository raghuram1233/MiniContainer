#!/usr/bin/env bash
# Convenience build wrapper for MiniContainer. Must be run inside WSL (or any
# native Linux) - the build tree must live on a real filesystem (ext4), never
# under /mnt/c, or the 9p/drvfs filesystem will make the build painfully slow
# and can break tools that rely on inotify or hardlinks.
#
# Usage: scripts/wsl-build.sh [--release] [--asan] [--tests-only] [--clean]
#
#   --release     Configure CMAKE_BUILD_TYPE=Release instead of Debug.
#   --asan        Enable MC_ENABLE_ASAN=ON (and UBSan alongside it).
#   --tests-only  Build only the test targets, then run ctest; skips building
#                 the minicontainer executable's dependents beyond what tests
#                 need (still configures the whole project - CMake doesn't
#                 support partial configuration, only partial build).
#   --clean       Remove the build directory before configuring.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
BUILD_DIR="${MC_BUILD_DIR:-${HOME}/mc-build}"

BUILD_TYPE="Debug"
ENABLE_ASAN="OFF"
TESTS_ONLY="0"
CLEAN="0"

for arg in "$@"; do
  case "${arg}" in
    --release) BUILD_TYPE="Release" ;;
    --asan) ENABLE_ASAN="ON" ;;
    --tests-only) TESTS_ONLY="1" ;;
    --clean) CLEAN="1" ;;
    -h|--help)
      sed -n '2,20p' "$0"
      exit 0
      ;;
    *)
      echo "wsl-build.sh: unknown argument: ${arg}" >&2
      exit 1
      ;;
  esac
done

case "${SOURCE_DIR}" in
  /mnt/c/*|/mnt/[a-zA-Z]/*)
    echo "wsl-build.sh: source is on a Windows drive mount (${SOURCE_DIR})." >&2
    echo "  That is expected - source lives on C:\\ - but note BUILD_DIR" >&2
    echo "  (${BUILD_DIR}) must stay on native ext4, which is the default here." >&2
    ;;
esac

case "${BUILD_DIR}" in
  /mnt/c/*|/mnt/[a-zA-Z]/*)
    echo "wsl-build.sh: refusing to build on a Windows drive mount: ${BUILD_DIR}" >&2
    echo "  Set MC_BUILD_DIR to a path on native ext4 (default: \$HOME/mc-build)." >&2
    exit 1
    ;;
esac

if [[ "${CLEAN}" == "1" && -d "${BUILD_DIR}" ]]; then
  echo "wsl-build.sh: removing ${BUILD_DIR}"
  rm -rf "${BUILD_DIR}"
fi

echo "wsl-build.sh: configuring (type=${BUILD_TYPE} asan=${ENABLE_ASAN}) into ${BUILD_DIR}"
cmake -S "${SOURCE_DIR}" -B "${BUILD_DIR}" -G Ninja \
  -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
  -DMC_ENABLE_ASAN="${ENABLE_ASAN}" \
  -DMC_ENABLE_UBSAN="${ENABLE_ASAN}"

NPROC="$(command -v nproc >/dev/null 2>&1 && nproc || echo 4)"

if [[ "${TESTS_ONLY}" == "1" ]]; then
  echo "wsl-build.sh: building test targets only"
  cmake --build "${BUILD_DIR}" -j"${NPROC}" --target mc_unit_tests mc_integration_tests || \
    cmake --build "${BUILD_DIR}" -j"${NPROC}"
else
  echo "wsl-build.sh: building all targets"
  cmake --build "${BUILD_DIR}" -j"${NPROC}"
fi

echo "wsl-build.sh: running ctest (excluding LABEL root - those need a privileged host)"
ctest --test-dir "${BUILD_DIR}" --output-on-failure -LE root || true

echo "wsl-build.sh: done. Build tree: ${BUILD_DIR}"
