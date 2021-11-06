#!/bin/bash
## \file
# \brief Process the standard input to extract the desired fields from readelf
#	output. Use \c do_symsize.sh to generate the tables for all targets.

# The number of symbol tables. Should be 1 but multiple symbol tables may exist.
NB_SYMTABS=0
# The headers of the fields to extract in the order they should appear in the
# output.
declare -a FMT_HEADERS
FMT_HEADERS=(
	"size"
	"type"
	"name"
)

##
# \brief Skip to the line that matches the regular expression
# \param 1 The regular expression of the line to skip to
# \retval 0 if a line that mathces the regular expression has been processed and
#	the pending standard input data is now the line that follows.
# \retval 1 if no match has been found and the standard input has reached EOF.
skip_to () {
	while read l; do
		if echo "$l" | egrep -q "$1"; then
			return 0
		fi
	done
	return 1
}

##
# \brief This is just like \c echo, except that it outputs to the standard
#	error, not output.
echo_err () {
	echo $@ >&2
}

##
# \brief Exit with error code and message.
# \param 1 (optional)The error message. No output is generated if empty string.
# \param 2 (optional)The exit code. Must be a numeric value that's accepted by
#	the OS. The default value 1 is used if empty string.
die () {
	local ec

	if [ ! -z "$1" ]; then
		echo_err "$1" >&2
	fi
	if [ -z "$2" ]; then
		ec=1
	else
		ec="$2"
	fi
	exit $ec
}

# For each symbol table
while skip_to "^[Ss]ymbol table '(\\.|\\w)+' contains [0-9]+ entries:\$"; do
	unset idx_map name_map
	declare -A idx_map name_map

	# Read the header line
	if ! read l; then
		die "Unexpected EOF"
	fi
	let 'NB_SYMTABS += 1'

	# Map the fields
	i=0
	for h in $l; do
		h="${h,,}"

		case "$h" in
		"num") idx_map["$h"]=$i ;;
		"value") idx_map["$h"]=$i ;;
		"size") idx_map["$h"]=$i ;;
		"type") idx_map["$h"]=$i ;;
		"bind") idx_map["$h"]=$i ;;
		"vis") idx_map["$h"]=$i ;;
		"ndx") idx_map["$h"]=$i ;;
		"name") idx_map["$h"]=$i ;;
		esac
		name_map["$i"]="$h"
		let 'i += 1'
	done

	# Check if all the fields desired are there
	for i in ${FMT_HEADERS[@]}; do
		if [ -z ${idx_map["$i"]} ]; then
			echo_err "Missing header in symbol table: ${FMT_HEADERS["$i"]}"
			die "Headers required in symbol table: ${FMT_HEADERS[*]}"
		fi
	done

	# For each entry line
	# Assume that the table ends with an empty line
	while read l && [ ! -z "$l" ]; do
		unset size type name

		i=0
		for w in $l; do
			case "${name_map[$i]}" in
			"size") size="$w" ;;
			"type") type="$w" ;;
			"name") name="$w" ;;
			"") die "Format error." ;;
			esac
			let 'i += 1'
		done

		if [ "$size" -eq 0 ]; then
			continue
		fi
		printf "%10u %c %s\n" $size ${type:0:1} $name
	done
done

# Treat input data with no symbol table as error
if [ $NB_SYMTABS -eq 0 ]; then
	die "No symbol table found."
fi
exit 0
