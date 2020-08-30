#!/bin/bash
sed -E -e "/^((\\s+)?#.*)?$/D" -e "s/\\s//g" | tr -d "\\n" | xxd -ps -r
