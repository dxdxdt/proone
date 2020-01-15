#!/bin/bash
ARCH_ARR=(
	"armv4t"
	"armv7"
	"i686"
	"m68k"
	"mips"
	"mpsl"
	"ppc"
	"sh4"
	"spc"
)
TOOLCHAIN_ARR=(
	"armv4t"
	"armv7"
	"i686"
	"m68k"
	"mips"
	"mpsl"
	"ppc"
	"sh4"
	"spc"
)
HOST_ARR=(
	"arm-linux"
	"arm-linux"
	"i686-linux"
	"m68k-linux"
	"mips-linux"
	"mipsel-linux"
	"powerpc-linux"
	"sh4-linux"
	"sparc-linux"
)
ARR_SIZE="${#ARCH_ARR[@]}"
if [ $ARR_SIZE -ne "${#TOOLCHAIN_ARR[@]}" ] || [ $ARR_SIZE -ne "${#HOST_ARR[@]}" ]; then
	echo "Config error: arrays" >&2
	exit 2
fi

PROONE_PREFIX="builds"
PROONE_ORG_BIN="$PROONE_PREFIX/out"
PROONE_REL_BIN="$PROONE_PREFIX/bin"
PROONE_TOOLS="$PROONE_PREFIX/tools"
export PROONE_ORG_BIN_PREFIX="$PROONE_ORG_BIN/proone"
export PROONE_REL_BIN_PREFIX="$PROONE_REL_BIN/proone"
PROONE_PACKER="$PROONE_TOOLS/proone-pack"
PROONE_UNPACKER="$PROONE_TOOLS/proone-unpack"
PROONE_BIN_ARCHIVE="$PROONE_PREFIX/bin-archive"

rm -rf "$PROONE_PREFIX" && mkdir "$PROONE_PREFIX" "$PROONE_ORG_BIN" "$PROONE_REL_BIN" "$PROONE_TOOLS"
if [ $? -ne 0 ] ; then
	exit $?
fi

make distclean

# native build for tools
./configure $PROONE_AM_CONF &&	make -j$(nproc) &&
	cp -a src/proone-pack "$PROONE_PACKER" &&
	cp -a src/proone-unpack "$PROONE_UNPACKER" &&
	cp -a src/proone-list-arch "$PROONE_TOOLS/proone-list-arch" &&
	cp -a src/proone-mask "$PROONE_TOOLS/proone-mask" &&
	cp -a src/proone-print-all-data "$PROONE_TOOLS/proone-print-all-data" &&
	cp -a src/proone-resolv "$PROONE_TOOLS/proone-resolv"
if [ $? -ne 0 ]; then
	exit $?
fi
make distclean

# cross-compile targets
for (( i = 0; i < ARR_SIZE; i += 1 )); do
	PROONE_HOST="${HOST_ARR[$i]}" PROONE_BIN_ARCH="${ARCH_ARR[$i]}" bash-xcomp-emb "${TOOLCHAIN_ARR[$i]}" "scripts/xcomp.sh"
	if [ $? -ne 0 ]; then
		exit $?
	fi
done

# pack
echo "bwEYAZaX8Zu9X1C6024h" > "$PROONE_BIN_ARCHIVE" # "test":"password"
"$PROONE_PACKER" "$PROONE_ORG_BIN_PREFIX."* | pigz -z - | base64 >> "$PROONE_BIN_ARCHIVE"
if [ $? -ne 0 ]; then
	exit $?
fi

# archive test


# size report
total_bin_size=$(cat "$PROONE_ORG_BIN_PREFIX."* | wc -c)
bin_archive_size=$(wc -c "$PROONE_BIN_ARCHIVE" | awk '{print $1;}')
echo "print(\"archive/bin = $bin_archive_size / $total_bin_size (\" + str($bin_archive_size / $total_bin_size * 100) + \"%)\")" | python3

exit 0
