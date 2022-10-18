#!/usr/bin/env python3
## \file
# \brief CNC TXT REC delete script

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

import sys
import re
import prne_txtrec

# regex for seperating the number of data RRs and the suffix from the head TXT
HEAD_TXT_RE = re.compile('"([0-9]{8})(.*)"')
# regex for seperating the index and the suffix from the data TXT
DATA_TXT_RE = re.compile('([0-9]{8})(.*)')

# Error definitions
HOOK_ERRORS = {
	"NOT_IMPL": {
		"msg": "not implemented",
		"ec": 1
	},
	"AWS_NO_BOTO3": {
		"msg": "Please install Boto3 for AWS hook",
		"ec": 1
	},
	"NO_RR": {
		"msg": "No RR in the zone specified",
		"ec": 1
	},
	"NO_HEAD_REC": {
		"msg": "The head rec not found",
		"ec": 1
	},
	"MULTI_HEAD_REC": {
		"msg": "The head rec has multiple TXT values",
		"ec": 1
	},
	"HEAD_REC_INV_FMT": {
		"msg": "Invalid format of the head TXT rec value",
		"ec": 1
	},
}

def main_aws (zone_id: str, head_rec: str):
	"""AWS hook main function"""
	try:
		import boto3
	except ModuleNotFoundError as e:
		prne_txtrec.handle_err(HOOK_ERRORS["AWS_NO_BOTO3"], e)

	client = boto3.client("route53")
	del_q = [] # List of RRs to be deleted

	# Get the head RR
	r = client.list_resource_record_sets(
		HostedZoneId = zone_id,
		StartRecordName = head_rec,
		StartRecordType = "TXT")
	rrs = r['ResourceRecordSets']

	# Handle general errors
	if len(rrs) <= 0:
		# No RR in the zone
		prne_txtrec.handle_err(HOOK_ERRORS["NO_RR"])
	if rrs[0]['Name'].lower() != head_rec:
		# If the list does not start with the head rec, which is
		# specifically requested, the head rec probably doesn't exist in the
		# zone.
		prne_txtrec.handle_err(HOOK_ERRORS["NO_HEAD_REC"])
	if len(rrs[0]['ResourceRecords']) > 1:
		# Multiple RR data. This is a protocol error - the scripts will
		# never allow RRs with muiltiple TXT values
		prne_txtrec.handle_err(HOOK_ERRORS["MULTI_HEAD_REC"])
	head_rr = rrs[0]

	# Seperate the number of records and the suffix
	head_txt = head_rr['ResourceRecords'][0]['Value']
	m = HEAD_TXT_RE.fullmatch(head_txt)
	if not m:
		prne_txtrec.handle_err(
			HOOK_ERRORS["HEAD_REC_INV_FMT"],
			None,
			head_txt if head_txt.isprintable() else None)
	nb_rr = int(m.group(1))
	suffix = prne_txtrec.termdot(m.group(2))

	# Go through all the records in the zone to delete the records that fall
	# into the criteria - suffix and the prefix number in range

	# Using these will start the list from the first record. Hopefully, the
	# server returns the list in order so that the script does not have to
	# visit the other irrelevant RRs in the zone
	next_name = "00000000" + suffix
	next_type = "TXT"
	while len(del_q) in range(0, nb_rr):
		r = client.list_resource_record_sets(
			HostedZoneId = zone_id,
			StartRecordName = next_name,
			StartRecordType = next_type)
		rrs = r['ResourceRecordSets']

		if not rrs:
			break
		if 'IsTruncated' in r and r['IsTruncated']:
			# Set up the tokens for the next iteration
			next_name = r['NextRecordName']
			next_type = r['NextRecordType']

		for rr in rrs:
			if rr['Type'] != "TXT":
				continue
			m = DATA_TXT_RE.fullmatch(rr['Name'])
			if not m or m.group(2).lower() != suffix:
				continue
			if not (int(m.group(1)) in range(0, nb_rr)):
				continue
			# Matches the criteria. Queue for deletion
			del_q.append(rr)

	while del_q:
		# Delete AWS_MAX_ITEMS RRs at a time as per recommendation
		prne_txtrec.change_all(
			client,
			zone_id,
			'DELETE',
			del_q[:min(len(del_q),
			prne_txtrec.AWS_MAX_ITEMS)])
		del del_q[:min(len(del_q), prne_txtrec.AWS_MAX_ITEMS)]
	# Finally, delete the head rec
	prne_txtrec.change_all(client, zone_id, 'DELETE', [head_rr])

HOOKS = {
	"aws": main_aws
}
USAGE_LINES = [
	"Usage: " + sys.argv[0] + " <head rec> <hook> <zone id>\n",
	"Hooks:\n"
]
for h in HOOKS:
	USAGE_LINES.append("  " + h + "\n")

def print_usage (out):
	out.writelines(USAGE_LINES)

# proecss argv
try:
	ARGV_DICT = {
		"head_rec": prne_txtrec.termdot(sys.argv[1].lower()),
		"hook": sys.argv[2].lower(),
		"zone_id": sys.argv[3]
	}
except IndexError:
	print_usage(sys.stderr)
	exit(1)

# call the function
try:
	HOOKS[ARGV_DICT["hook"]](ARGV_DICT["zone_id"], ARGV_DICT["head_rec"])
except KeyError:
	prne_txtrec.handle_err(HOOK_ERRORS["NOT_IMPL"], None, ARGV_DICT["hook"])

exit(0)
