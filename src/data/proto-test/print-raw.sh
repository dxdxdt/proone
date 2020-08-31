#!/bin/bash
sed -E -e "s/((\\s+)?#.*)?$//" -e "/^(\\s+)?$/D" -e "s/\\s//g" | tr -d "\\n" | xxd -ps -r
