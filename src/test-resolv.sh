#!/bin/bash
assert_ec () {
	echo -n "$3: " >&2
	if [ $1 -ne $2 ]; then
		echo "FAIL (expected=$2, returned=$1)" >&2
		exit 1
	else
		echo "OK" >&2
	fi
}
SUBJECT_EXEC="./proone-resolv"

echo "a example.com" | "$SUBJECT_EXEC"
assert_ec $? 0 "Single NOERROR execution"

echo "a example.test" | "$SUBJECT_EXEC"
assert_ec $? 0 "Single NXDOMAIN execution"

cat << EOF | "$SUBJECT_EXEC"
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

cat << EOF | "$SUBJECT_EXEC"
aaaa example.com
txt example.test
EOF
assert_ec $? 0 "Mixed result"
