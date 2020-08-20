#!/bin/bash
cmd_align-size () {
	local aligned
	
	if [ $# -lt 2 ]; then
		echo "Usage: $0 <alignment> <size>" >&2
		return 2
	fi

	let "aligned = $2 % $1"
	if [ $aligned -eq 0 ]; then
		aligned=$2
	else
		let "aligned = ($2 / $1 + 1) * $1"
	fi

	echo $aligned

	return 0
}

cmd_align-file () {
	if [ $# -lt 2 ]; then
		echo "Usage: $0 <alignment> <file>" >&2
		return 2
	fi

	truncate -s $("$SELF" align-size "$1" $(stat -c "%s" $2)) "$2"
}

cmd_append-uint32 () {
	local a b c d

	if [ $# -lt 2 ]; then
		echo "Usage: $0 <value> <file>" >&2
		return 2
	fi

	let "a = ($1 & 0xFF000000) >> 24"
	let "b = ($1 & 0x00FF0000) >> 16"
	let "c = ($1 & 0x0000FF00) >> 8"
	let "d = ($1 & 0x000000FF) >> 0"
	a=$(printf "%X" $a)
	b=$(printf "%X" $b)
	c=$(printf "%X" $c)
	d=$(printf "%X" $d)
	printf "\\x$a\\x$b\\x$c\\x$d" >> "$2"
}

cmd_append-uint16 () {
	local a b

	if [ $# -lt 2 ]; then
		echo "Usage: $0 <value> <file>" >&2
		return 2
	fi

	let "a = ($1 & 0xFF00) >> 8"
	let "b = ($1 & 0x00FF) >> 0"
	a=$(printf "%X" $a)
	b=$(printf "%X" $b)
	printf "\\x$a\\x$b" >> "$2"
}

SELF="$0"
cmd="$1"
shift 1

"cmd_$cmd" $@
