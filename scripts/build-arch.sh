#!/bin/bash
set -e

MISC_BIN="
	proone-stress
	proone-resolv
	proone-test_proto
	proone-test_util
"

separate_debug() {
	cp -a "$1" "$2"
	"$PROONE_HOST-objcopy" --only-keep-debug "$2" "$3"
	"$PROONE_HOST-strip" -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr "$2"
	"$PROONE_HOST-objcopy" --add-gnu-debuglink="$3" "$2"
}

BIN_PATH="$PROONE_EXEC_PREFIX.$PROONE_BIN_ARCH"

./configure --host="$PROONE_HOST" $PROONE_AM_CONF
cd src
make -j$(nproc) proone.bin $MISC_BIN
cd ..

separate_debug src/proone.bin "$BIN_PATH" "$PROONE_DEBUG_SYM_PREFIX""proone.sym.$PROONE_BIN_ARCH"
for b in $MISC_BIN; do
	separate_debug "src/$b" "$PROONE_MISC_BIN_PREFIX/$b.$PROONE_BIN_ARCH" "$PROONE_DEBUG_SYM_PREFIX""$b.sym.$PROONE_BIN_ARCH"
done

make distclean
