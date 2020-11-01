#!/bin/bash
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
