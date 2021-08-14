#!/bin/bash
NB_SYMTABS=0
declare -a FMT_HEADERS
FMT_HEADERS=(
	"size"
	"type"
	"name"
)

#
# \param 1: re of the line to skip to
skip_to () {
	while read l; do
		if echo "$l" | egrep -q "$1"; then
			return 0
		fi
	done
	return 1
}

#
# \param *: message
echo_err () {
	echo $@ >&2
}

#
# \param 1: (optional)message
# \param 2: (optional)exit code
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

while skip_to "^[Ss]ymbol table '(\\.|\\w)+' contains [0-9]+ entries:\$"; do
	unset idx_map name_map
	declare -A idx_map name_map

	if ! read l; then
		die "Unexpected EOF"
	fi
	let 'NB_SYMTABS += 1'

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

	for i in ${FMT_HEADERS[@]}; do
		if [ -z ${idx_map["$i"]} ]; then
			echo_err "Missing header in symbol table: ${FMT_HEADERS["$i"]}"
			die "Headers required in symbol table: ${FMT_HEADERS[*]}"
		fi
	done

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

if [ $NB_SYMTABS -eq 0 ]; then
	die "No symbol table found."
fi
exit 0
