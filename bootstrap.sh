#!/bin/sh
if [ $# -ne 0 ]; then
	cat >&2 << EOF
Bootstrap the project directory for Autoconf and Automake. Run this script after
making changes to .ac and .am files.
Usage: $0

The script requires that no argument is passed in order to run.
EOF
	exit 2
fi

aclocal &&
	automake --add-missing --copy &&
	autoconf &&
	autoheader
