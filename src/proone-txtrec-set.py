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
import getopt

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

BYTES_PER_RR = 189

def mktxtrr (cnt: int, suffix: str):
	return "%08u" % (cnt) + suffix

def main_aws (param: dict):
	"""AWS hook main function"""

	zone_id = param["zone_id"];
	if zone_id is None:
		sys.stderr.writelines([
			"--zone-id required.\n",
			"Run '{0} --help' for help.\n".format(sys.argv[0])
		])
		exit(2)
	head_rec = param["head_rec"]
	suffix = param["suffix"]
	ttl = param["ttl"]
	if ttl is None: ttl = 3600

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
		b = sys.stdin.buffer.read(BYTES_PER_RR)
		if not b: # Assume that EOF is reached
			break

		ins_q.append({
			'Name': mktxtrr(cnt, suffix),
			'Type': 'TXT',
			'TTL': ttl,
			'ResourceRecords': [
				{ 'Value': '"' + base64.b64encode(b).decode('ascii') + '"' }
			]
		})
		cnt += 1
		if len(ins_q) >= prne_txtrec.AWS_MAX_ITEMS:
			flush_q()

	flush_q()
	head_rr = mktxtrr(cnt, suffix)
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

def main_dnsmasq (param: dict):
	head_rec = param["head_rec"]
	suffix = param["suffix"]
	ttl = param["ttl"]

	if ttl is None: ttl_str = ""
	else: ttl_str = ",%us" % ttl

	cnt = 0
	while True:
		b = sys.stdin.buffer.read(BYTES_PER_RR)
		if not b: # EOF
			break

		name = mktxtrr(cnt, suffix)
		l = '''txt-record={name},"{val}"{ttl}'''.format(
			name = name,
			val = base64.b64encode(b).decode('ascii'),
			ttl = ttl_str
		)
		cnt += 1

		print(l)

	head_rr = mktxtrr(cnt, suffix)
	l = '''txt-record={name},"{val}"{ttl}'''.format(
		name = head_rec,
		val = head_rr,
		ttl = ttl_str
	)
	print(l)


HOOKS = {
	"aws": main_aws,
	"dnsmasq": main_dnsmasq
}
USAGE_STR = '''Upload or output Proone CNC TXT DNS records
Usage: {arg0} <options>
Options:
  -h, --help       print this message and exit normally
  -V, --version    print version info and exit normally
  --hook=<str>     (required) use the hook. See below for available hooks
  --head=<str>     (required) set the name of the header CNC TXT record
  --suffix=<str>   (required) set the suffix of the data CNC TXT record(s)
  --zond-id=<str>  set the zone id. Required for AWS hook
  --ttl=<uint>     specify TTL of the records
Hooks:
  {hooks}
'''.format(
	arg0 = sys.argv[0],
	hooks = "  ".join(k + "\n" for k in HOOKS.keys())
)

def print_usage (out):
	out.write(USAGE_STR)


opts, args = getopt.getopt(
	sys.argv[1:],
	"hV",
	[
		"help",
		"version",
		"hook=",
		"head=",
		"suffix=",
		"zone-id=",
		"ttl="
	])
opts = dict(opts)

if set(opts.keys()).intersection(set([ "--help", "-h", "--version", "-V" ])):
	if "--version" in opts or "-V" in opts:
		print("prne-txtrec version: " + prne_txtrec.VERSION)
	if "--help" in opts or "-h" in opts:
		print_usage(sys.stdout)
	exit(0)


# process argv
try:
	ARGV_DICT = {}
	ARGV_DICT["hook"] = opts["--hook"]
	ARGV_DICT["head_rec"] = opts["--head"]
	ARGV_DICT["suffix"] = opts["--suffix"]
	ARGV_DICT["zone_id"] = opts.get("--zone-id")
	ARGV_DICT["ttl"] = opts.get("--ttl")
	if ARGV_DICT["ttl"]:
		ARGV_DICT["ttl"] = int(ARGV_DICT["ttl"])
		if ARGV_DICT["ttl"] not in range(0, 2147483648):
			prne_txtrec.handle_err(
				HOOK_ERRORS["INV_ARG"],
				None,
				ARGV_DICT["ttl"])
except KeyError as e:
	sys.stderr.writelines([
		e.args[0] + " option required.\n",
		"Run '{0} --help' for help.\n".format(sys.argv[0])
	])
	exit(2)

# call the function
try:
	HOOKS[ARGV_DICT["hook"]](ARGV_DICT)
except KeyError:
	prne_txtrec.handle_err(HOOK_ERRORS["NOT_IMPL"], None, ARGV_DICT["hook"])

exit(0)
