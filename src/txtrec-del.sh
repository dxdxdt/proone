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

ARR_HOOKS="
	aws
"

if [ $# -lt 2 ]; then
	echo "Usage: $0 <head rec> <hook> <zone id>
Hooks:" >&2
	for h in $ARR_HOOKS; do
		echo -e "\t$h"
	done

	exit 2
fi

HEAD_REC="$1"
HOOK="$2"
ZONE_ID="$3"

aws_param () {
	cat << EOF
{
	"Changes": [
		{
			"Action": "DELETE",
			"ResourceRecordSet": $1
		}
	]
}
EOF
}

hook_aws () {
	local tmpfile=`mktemp --tmpdir txtrec-del.XXXXXXXXXX`

	aws route53 list-resource-record-sets\
		--hosted-zone-id "$ZONE_ID" > "$tmpfile"
	local nb_rec=`jq ".ResourceRecordSets | length" "$tmpfile"`
	local escaped_name=$(echo "$HEAD_REC" | sed -e s/\\./\\\\./g)

	for (( i = 0; i < nb_rec; i += 1 )); do
		local rec=$(jq ".ResourceRecordSets[$i]" "$tmpfile")
		jq ".ResourceRecordSets[$i].Name" "$tmpfile" |
			egrep -i "\"([0-9a-f]+\.)?$escaped_name\.?\""
		if [ $? -eq 0 ]; then
			aws route53 change-resource-record-sets\
				--hosted-zone-id "$ZONE_ID"\
				--change-batch "$(aws_param "$rec")"
		fi
	done

	rm -f "$tmpfile"
}

"hook_$HOOK" "$HEAD_REC"

i=0
while true; do
	"hook_$HOOK" $i."$HEAD_REC"
	if [ $? -ne 0 ]; then
		break
	fi
	let i=i+1
done
