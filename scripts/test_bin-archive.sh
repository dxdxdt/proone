#!/bin/bash
RND_BLOCK_SIZE=4096
if [ -z "$RND_BIN_CNT_MIN" ]; then
	RND_BIN_CNT_MIN=1
fi
if [ -z "$RND_BIN_CNT_MAX" ]; then
	RND_BIN_CNT_MAX=20
fi
TEST_DIR="pack_test"
BIN_PACK_DIR="$TEST_DIR/pack"
BIN_UNPACK_DIR="$TEST_DIR/unpack"
BIN_PREFIX="bin"
BIN_ARCHIVE_PREFIX="bin_archive"
SIZE_LOG="pack_test-size.log"
if [ -z "$LISTARCH" ]; then
	LISTARCH="../src/proone-list-arch"
fi
if [ -z "$PACKER" ]; then
	PACKER="../src/proone-pack"
fi
if [ -z "$UNPACKER" ]; then
	UNPACKER="../src/proone-unpack"
fi
ARCH_ARR=(`"$LISTARCH"`)

if [ -d "$TEST_DIR" ]; then
	rm -rf "$TEST_DIR/"*
else
	mkdir "$TEST_DIR"
fi
mkdir "$BIN_PACK_DIR" "$BIN_UNPACK_DIR"
if [ $? -ne 0 ]; then
	exit 2
fi

for arch in ${ARCH_ARR[@]}; do
	bin_block_cnt="$(shuf -n1 -i $RND_BIN_CNT_MIN-$RND_BIN_CNT_MAX)" &&\
		dd if=/dev/random of="$BIN_PACK_DIR/$BIN_PREFIX.$arch" iflag=fullblock bs=$RND_BLOCK_SIZE count=$bin_block_cnt
	if [ $? -ne 0 ]; then
		exit 2
	fi
done

"$PACKER" "$BIN_PACK_DIR/$BIN_PREFIX."* | pigz -z - | base64 > "$TEST_DIR/$BIN_ARCHIVE_PREFIX"
if [ $? -ne 0 ]; then
	exit 2;
fi

"$UNPACKER" "$BIN_UNPACK_DIR/$BIN_PREFIX" < "$TEST_DIR/$BIN_ARCHIVE_PREFIX"
if [ $? -ne 0 ]; then
	exit 2;
fi

for arch in ${ARCH_ARR[@]}; do
	diff -q "$BIN_PACK_DIR/$BIN_PREFIX.$arch" "$BIN_UNPACK_DIR/$BIN_PREFIX.$arch"
	if [ $? -ne 0 ]; then
		exit 2;
	fi
done

echo $(du -bs "$BIN_PACK_DIR" | awk '{print $1;}') $(wc -c "$TEST_DIR/$BIN_ARCHIVE_PREFIX" | awk '{print $1;}') >> "$SIZE_LOG"

exit 0
