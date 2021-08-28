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

assert_ec () {
	echo -n "$3: " >&2
	if [ $1 -ne $2 ]; then
		echo "FAIL (expected=$2, returned=$1)" >&2
		exit 1
	else
		echo "OK" >&2
	fi
}
SUBJECT_EXEC="valgrind --leak-check=full --show-leak-kinds=all -- ./proone-resolv"

echo "a example.com" | $SUBJECT_EXEC
assert_ec $? 0 "Single NOERROR execution"

echo "a example.test" | $SUBJECT_EXEC
assert_ec $? 0 "Single NXDOMAIN execution"

cat << EOF | $SUBJECT_EXEC
; Queue more than RESOLV_PIPELINE_SIZE(4)
a example.com
aaaa example.com
a www.example.com
aaaa www.example.com
txt kernel.org
a www.google.com
aaaa www.google.com
txt example.com
a www.kernel.org
aaaa www.kernel.org
EOF
assert_ec $? 0 "Queue congestion"

cat << EOF | $SUBJECT_EXEC
aaaa example.com
txt example.test
EOF
assert_ec $? 0 "Mixed result"
