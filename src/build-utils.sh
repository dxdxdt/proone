#!/bin/bash

# Copyright (c) 2019-2021 David Timber <mieabby@gmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

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
