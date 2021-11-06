#!/bin/bash
## \file
# \brief Generate the text files of the symbol size table from the readelf
#	output. The values are separated by white spaces. Only 3 fields are
#	extracted in order: the size of symbol in decimal, the type of the symbol
#	and the name of the symbol. The text files can be imported into spreadsheet
#	or document files to make the tables a printable form.

# The input prefix
ELF_PREFIX='./builds/proone.bin/readelf'
# The output prefix
OUT_PREFIX='./builds/proone.bin/symsize'
# The number of threads on the host
NPROC=$(nproc)
# The number of concurrent processes
NB_PROC=0

##
# \brief Call the script that actually does the job
# \param 1 input file
# \param 2 output file
call_extsymsize () {
	./scripts/extsymsize.sh < "$1" | sort -nr > "$2"
}

# Process each readelf output file
for f in "$ELF_PREFIX".*; do
	# Extract the arch from the file name
	# The script assumes that the "middle name" is the name of the arch
	suffix=$(echo "$f" | egrep -o '(\.\w+\.\w+)$')
	if [ $? -ne 0 ]; then
		echo "$f: invalid suffix" >&2
		exit 1
	fi

	# Die on error: while running \c extsymsize.sh or in the process of
	# launching it
	set -e
	out="$OUT_PREFIX""$suffix"
	# Limit the number of processses running concurrently to the number of
	# threads on the host.
	if [ $NB_PROC -lt $NPROC ]; then
		call_extsymsize "$f" "$out" &
		let 'NB_PROC += 1'
	else
		wait
		call_extsymsize "$f" "$out" &
	fi
	set +e
done

# Reap processes
for (( i = 0; i < NB_PROC; i += 1 )); do
	wait
done
