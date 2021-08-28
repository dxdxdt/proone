#!/bin/bash
gen () {
	local out="$1"
	local head="$2"
	local foot="$3"
	local lprefix="$4"
	local lsuffix="$5"
	local l

	echo "$head" > "$out"
	while read l; do
		echo "$lprefix$l$lsuffix" >> "$out"
	done
	echo "$foot" >> "$out"
}

PATH_COPYING="COPYING"
OUT_PREFIX="COPYING"

gen "$OUT_PREFIX.line" "" "" "" "" < "$PATH_COPYING"
gen "$OUT_PREFIX.c" "/*" "*/" "* " "" < "$PATH_COPYING"
gen "$OUT_PREFIX.sharp" "" "" "# " "" < "$PATH_COPYING"
gen "$OUT_PREFIX.xml" "<!--" "-->" "	" "" < "$PATH_COPYING"
gen "$OUT_PREFIX.dd" "--" "--" "-- " "" < "$PATH_COPYING"
