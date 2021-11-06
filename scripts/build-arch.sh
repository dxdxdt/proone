#!/bin/bash
## \file
# \brief Build one target. Usually, this script is run by build-all.sh although
#	it can be run standalone by setting all the required environment variables
#	by hand.
set -e

# Miscellaneous executables
MISC_BIN="
	proone-stress
	proone-resolv
	proone-test_proto
	proone-test_util
"
# Proone executable output path
BIN_PATH="$PROONE_EXEC_PREFIX.$PROONE_BIN_OS.$PROONE_BIN_ARCH"
# Unstripped Proone executable output path
ENTIRE_BIN_PATH="$PROONE_ENTIRE_PREFIX.$PROONE_BIN_OS.$PROONE_BIN_ARCH"
# Path to readelf output of unstripped executable
READELF_PATH="$PROONE_READELF_PREFIX.$PROONE_BIN_OS.$PROONE_BIN_ARCH"
# Disassembler output path (unused)
ASM_PATH="$PROONE_ASM_PREFIX.$PROONE_BIN_OS.$PROONE_BIN_ARCH"

##
# \brief Separate debug symbols from an executable
# \param[in] 1 the input executable
# \param[out] 2 the stripped executable for release build
# \param[out] 3 the debug symbols
# \param[out] 4 (optional)a copy of \p 1
# \note This is a convenience function for creating various binary files from
#	the compiler executable output. The two types of files, the stripped
#	executable and the debug symbol, should be kept for each release in order to
#	analyse core dumps.
# \note When \p 4 is used, the function copies \p 1 to \p 4 and
#	dumps the output of readelf to \c $READELF_PATH.
separate_debug() {
	cp -a "$1" "$2"
	if [ ! -z "$4" ]; then
		cp -a "$1" "$4"
		"$PROONE_HOST"-readelf -a "$4" > "$READELF_PATH"
		# "$PROONE_HOST"-objdump -D "$4" | xz -evvT0 > "$ASM_PATH"
	fi
	"$PROONE_HOST-objcopy" --only-keep-debug "$2" "$3"
	"$PROONE_HOST-strip"\
		-S\
		--strip-unneeded\
		--remove-section=.note.gnu.gold-version\
		--remove-section=.comment\
		--remove-section=.note\
		--remove-section=.note.gnu.build-id\
		--remove-section=.note.ABI-tag\
		--remove-section=.jcr\
		--remove-section=.got.plt\
		--remove-section=.eh_frame\
		--remove-section=.eh_frame_ptr\
		--remove-section=.eh_frame_hdr\
		"$2"
	"$PROONE_HOST-objcopy" --add-gnu-debuglink="$3" "$2"
}

# do build
./configure --host="$PROONE_HOST" --enable-static $PROONE_AM_CONF
cd src
make -j$(nproc) proone.bin $MISC_BIN
cd ..

# extract output
separate_debug\
	src/proone.bin\
	"$BIN_PATH"\
	"$PROONE_DEBUG_SYM_PREFIX""proone.sym.$PROONE_BIN_OS.$PROONE_BIN_ARCH"\
	"$ENTIRE_BIN_PATH"
for b in $MISC_BIN; do
	separate_debug\
		"src/$b"\
		"$PROONE_MISC_BIN_PREFIX/$b.$PROONE_BIN_OS.$PROONE_BIN_ARCH"\
		"$PROONE_DEBUG_SYM_PREFIX""$b.sym.$PROONE_BIN_OS.$PROONE_BIN_ARCH"
done

# clean up for the next arch build
make distclean
