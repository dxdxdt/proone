#!/bin/bash
ELF_PREFIX='./builds/proone.bin/readelf'
OUT_PREFIX='./builds/proone.bin/symsize'
NPROC=$(nproc)
NB_PROC=0

#
# \param 1: input file
# \param 2: output file
call_extsymsize () {
	./scripts/extsymsize.sh < "$1" | sort -nr > "$2"
}

for f in "$ELF_PREFIX".*; do
	suffix=$(echo "$f" | egrep -o '(\.\w+\.\w+)$')
	if [ $? -ne 0 ]; then
		echo "$f: invalid suffix" >&2
		exit 1
	fi

	set -e
	out="$OUT_PREFIX""$suffix"
	if [ $NB_PROC -lt $NPROC ]; then
		call_extsymsize "$f" "$out" &
		let 'NB_PROC += 1'
	else
		wait
		call_extsymsize "$f" "$out" &
	fi
	set +e
done

for (( i = 0; i < NB_PROC; i += 1 )); do
	wait
done
