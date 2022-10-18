#!/bin/bash
## \file
# \brief Convenience shell functions for fabrication of Proone executables
# \param 1 The subcommand. One of align-size, align-file, append-uint32 or
# 	append-uint16
# \param 2 or greator: arguments to the subcommand.
# \note These shell functions are used in the Automake recipe to facilitate
#	extra unconventional steps to build Proone executables.

# Copyright (c) 2019-2022 David Timber <dxdt@dev.snart.me>
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

##
# \brief Align size x to y
# \param 1 The alignment.
# \param 2 The size to align.
# \return The aligned size.
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

##
# \brief Align the size of the file using truncate
# \param 1 The alignment.
# \param 2 The path to the file to align.
cmd_align-file () {
	if [ $# -lt 2 ]; then
		echo "Usage: $0 <alignment> <file>" >&2
		return 2
	fi

	truncate -s $("$SELF" align-size "$1" $(stat -c "%s" $2)) "$2"
}

##
# \brief Append a 32-bit unsigned integer to the file, MSB first
# \param 1 The integer value to append
# \param 2 The file to append the integer to
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

##
# \brief Append a 16-bit unsigned integer to the file, MSB first
# \param 1 The integer value to append
# \param 2 The file to append the integer to
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

# Invoke subcommand
SELF="$0"
cmd="$1"
shift 1

"cmd_$cmd" $@
