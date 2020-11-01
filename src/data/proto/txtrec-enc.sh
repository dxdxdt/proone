#!/bin/bash
if [ $# -lt 1 ]; then
	echo "Usage: $0 <prefix>" >&2
	exit 2
fi

set -e
cnt=0
while true; do
	rec="$(dd bs=189 count=1 status=none | base64 -w0)"
	if [ -z "$rec" ]; then
		break
	fi

	printf "%08X%s %s\n" $cnt "$1" "$rec"
	let "cnt += 1"
done

printf "\n%08x%s\n" $cnt "$1"
