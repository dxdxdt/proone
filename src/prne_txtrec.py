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
import sys
from typing import Iterable

# AWS hook - The max number of objects in a request
AWS_MAX_ITEMS = 1000

## Handle error according to the error definition
# @param o the error definition
# @param e the exception (optional)
# @param m the error message header, perror() param equiv (optional)
# @note The function will call \c exit() if the error definition dictates to do
# 	so
def handle_err (o, e, m):
	if e:
		sys.stderr.write(e + "\n\n")
	if m:
		l = m + ": " + o["msg"] + "\n"
	else:
		l = o["msg"] + "\n"

	sys.stderr.write(l)
	if "ec" in o:
		exit(o["ec"])

## Append a dot(".") to the string if it does not end with the dot
def termdot (str: str):
	if not str.endswith("."):
		return str + "."
	return str

# Change all RRs specified in the iterable
def change_all (client, zone_id: str, action: str, it: Iterable):
	c_arr = []
	for rr in it:
		c_arr.append({
			'Action': action,
			'ResourceRecordSet': rr
		})
	cb = { 'Changes': c_arr }

	return client.change_resource_record_sets(
			HostedZoneId = zone_id,
			ChangeBatch = cb
		)
