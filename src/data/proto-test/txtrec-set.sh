#!/bin/bash
set -e

ARR_HOOKS="
	aws
"

if [ $# -lt 2 ]; then
	echo "Usage: $0 <head rec> <hook> <zone id> [TTL]
Hooks:" >&2
	for h in $ARR_HOOKS; do
		echo -e "\t$h"
	done

	exit 2
fi

HEAD_REC="$1"
HOOK="$2"
ZONE_ID="$3"
if [ -z "$4" ]; then
	TTL=3600
else
	TTL="$4"
fi

aws_param () {
	cat << EOF
{
	"Changes": [
		{
			"Action": "UPSERT",
			"ResourceRecordSet": {
				"Name": "$1",
				"Type": "TXT",
				"TTL": $TTL,
				"ResourceRecords": [
					{ "Value": "\"$2\"" }
				]
			}
		}
	]
}
EOF
}

hook_aws () {
	aws route53 change-resource-record-sets\
		--hosted-zone-id "$ZONE_ID"\
		--change-batch "$(aws_param "$1" "$2")"
}

while read line; do
	if [ -z "$line" ]; then
		break;
	fi
	"hook_$HOOK" $line
done

read line
"hook_$HOOK" "$HEAD_REC" "$line"
