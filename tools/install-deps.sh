#!/usr/bin/env bash
# Install the system packages needed to build callgraph.
#
# Required: C++20 compiler, CMake >= 3.20, clang with the BPF target,
# pkg-config, libelf, libdw, zlib, git, make.
# Optional: libcurl (network OTLP), protobuf/protoc (OTLP gRPC and HTTP
# protobuf), binutils-dev (libopcodes for --return-mode=ret), python3 (tests).
#
# Usage:
#   ./tools/install-deps.sh                 # required + optional packages
#   ./tools/install-deps.sh --minimal       # required packages only
#   ./tools/install-deps.sh --skip-submodules
#   ./tools/install-deps.sh --dry-run
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd -- "${SCRIPT_DIR}/.." && pwd)

MINIMAL=0
DRY_RUN=0
SKIP_SUBMODULES=0

usage()
{
    sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'
}

die()
{
    printf 'error: %s\n' "$*" >&2
    exit 1
}

warn()
{
    printf 'warning: %s\n' "$*" >&2
}

log()
{
    printf '==> %s\n' "$*"
}

run()
{
    if (( DRY_RUN )); then
        printf '  '
        printf '%q ' "$@"
        printf '\n'
    else
        "$@"
    fi
}

while (($# > 0)); do
    case "$1" in
        --minimal)
            MINIMAL=1
            ;;
        --skip-submodules)
            SKIP_SUBMODULES=1
            ;;
        --dry-run)
            DRY_RUN=1
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "unknown option '$1' (use --help)"
            ;;
    esac
    shift
done

[[ -r /etc/os-release ]] || die "cannot read /etc/os-release"
. /etc/os-release

DISTRO_ID=${ID:-unknown}
DISTRO_LIKE=${ID_LIKE:-}
FAMILY=
PKG_MANAGER=
REQUIRED=()
OPTIONAL=()

case " ${DISTRO_ID} ${DISTRO_LIKE} " in
    *debian*|*ubuntu*)
        FAMILY=debian
        PKG_MANAGER=apt-get
        REQUIRED=(
            build-essential cmake git pkg-config clang
            libelf-dev libdw-dev zlib1g-dev
        )
        OPTIONAL=(
            libcurl4-openssl-dev
            protobuf-compiler libprotobuf-dev
            binutils-dev
            python3
        )
        ;;
    *rhel*|*fedora*|*centos*|*rocky*|*almalinux*)
        FAMILY=rhel
        if command -v dnf >/dev/null 2>&1; then
            PKG_MANAGER=dnf
        else
            PKG_MANAGER=yum
        fi
        REQUIRED=(
            gcc-c++ make cmake git pkgconfig clang
            elfutils-libelf-devel elfutils-devel zlib-devel
        )
        OPTIONAL=(
            libcurl-devel
            protobuf-compiler protobuf-devel
            binutils-devel
            python3
        )
        ;;
    *arch*)
        FAMILY=arch
        PKG_MANAGER=pacman
        REQUIRED=(
            base-devel cmake git pkgconf clang
            libelf elfutils zlib
        )
        OPTIONAL=(
            curl protobuf binutils python
        )
        ;;
    *suse*|*opensuse*)
        FAMILY=suse
        PKG_MANAGER=zypper
        REQUIRED=(
            gcc-c++ make cmake git pkg-config clang
            libelf-devel libdw-devel zlib-devel
        )
        OPTIONAL=(
            libcurl-devel
            protobuf-devel protobuf-compiler
            binutils-devel
            python3
        )
        ;;
    *)
        cat >&2 <<EOF
error: unsupported distribution '${DISTRO_ID} ${DISTRO_LIKE}'.

Install the equivalents of these packages manually:
  CMake >= 3.20, a C++20 compiler, make, git, pkg-config
  clang with the BPF target
  libelf development files
  libdw development files (elfutils)
  zlib development files

Optional:
  libcurl development files
  protobuf compiler and C++ development files
  binutils development files (libopcodes)
  python3 (tests)
EOF
        exit 1
        ;;
esac

if (( EUID == 0 )); then
    SUDO=()
elif command -v sudo >/dev/null 2>&1; then
    SUDO=(sudo)
else
    die "run as root or install sudo"
fi

install_packages()
{
    case "$FAMILY" in
        debian)
            run "${SUDO[@]}" apt-get install -y --no-install-recommends "$@"
            ;;
        rhel)
            run "${SUDO[@]}" "$PKG_MANAGER" install -y "$@"
            ;;
        arch)
            run "${SUDO[@]}" pacman -S --needed --noconfirm "$@"
            ;;
        suse)
            run "${SUDO[@]}" zypper --non-interactive install "$@"
            ;;
    esac
}

if [[ "$FAMILY" == "debian" ]]; then
    log "Refreshing apt package lists"
    run "${SUDO[@]}" apt-get update
elif [[ "$FAMILY" == "suse" ]]; then
    log "Refreshing zypper metadata"
    run "${SUDO[@]}" zypper --non-interactive refresh
fi

log "Installing required build packages"
install_packages "${REQUIRED[@]}"

if (( ! MINIMAL )); then
    log "Installing optional feature packages"
    if ! install_packages "${OPTIONAL[@]}"; then
        warn "some optional packages could not be installed; the base build will still work"
        warn "OTLP/HTTP and OTLP/gRPC may be unavailable without libcurl/protobuf"
    fi
fi

if (( SKIP_SUBMODULES == 0 )); then
    if command -v git >/dev/null 2>&1 &&
        git -C "$ROOT_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        log "Initializing the vendored libbpf submodule"
        run git -C "$ROOT_DIR" submodule update --init --recursive
    else
        warn "not inside a git work tree; skipping submodule initialization"
    fi
fi

if (( DRY_RUN )); then
    log "dry run complete; no changes were made"
    exit 0
fi

# Verify the tools that CMake/BPF compilation actually need.
check_failure=0

if ! command -v cmake >/dev/null 2>&1; then
    warn "cmake is not installed"
    check_failure=1
else
    cmake_version=$(cmake --version | awk 'NR == 1 { print $3 }')
    if [[ -z "$cmake_version" ]] ||
        [[ "$(printf '%s\n%s\n' "3.20" "$cmake_version" | sort -V | head -n1)" != "3.20" ]]; then
        warn "CMake ${cmake_version:-unknown} is older than the required 3.20"
        warn "install a newer CMake (for example from Kitware or your distro's cmake package)"
        check_failure=1
    fi
fi

if ! command -v clang >/dev/null 2>&1; then
    warn "clang is not installed"
    check_failure=1
elif ! clang -print-targets 2>/dev/null | grep -Eq '^[[:space:]]*bpf[[:space:]]'; then
    warn "clang does not report a BPF target; the eBPF object will not compile"
    check_failure=1
fi

if ! command -v pkg-config >/dev/null 2>&1; then
    warn "pkg-config is not installed"
    check_failure=1
else
    if ! pkg-config --exists libelf; then
        warn "pkg-config cannot find libelf"
        check_failure=1
    fi
    if ! pkg-config --exists libdw; then
        warn "pkg-config cannot find libdw"
        check_failure=1
    fi
fi

if ! command -v g++ >/dev/null 2>&1; then
    warn "g++ is not installed"
    check_failure=1
fi

if (( check_failure != 0 )); then
    die "required build dependencies are incomplete"
fi

if command -v protoc >/dev/null 2>&1; then
    log "protobuf/protoc found: OTLP/gRPC and OTLP/HTTP-protobuf enabled"
else
    warn "protoc not found: OTLP/gRPC and OTLP/HTTP-protobuf will be disabled"
fi

if pkg-config --exists libcurl 2>/dev/null; then
    log "libcurl found: network OTLP export enabled"
else
    warn "libcurl not found: network OTLP export will be disabled"
fi

if [[ -f /usr/include/dis-asm.h ]] || pkg-config --exists bfd 2>/dev/null; then
    log "libopcodes headers found: --return-mode=ret available"
else
    warn "libopcodes headers not found: --return-mode=ret will be unavailable"
fi

printf '\nDependencies are ready. From %s:\n' "$ROOT_DIR"
printf '  git submodule update --init --recursive\n'
printf '  cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo\n'
printf '  cmake --build build -j\n'
printf '\nTests:\n'
printf '  ./build/callgraph_tests\n'
printf '  sudo bash tests/integration.sh ./build/callgraph\n'
