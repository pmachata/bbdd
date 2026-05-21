#!/bin/bash

tests_dir=$(dirname "$(readlink -e "${BASH_SOURCE[0]}")")

for t in "$@"; do
	${tests_dir}/run1.sh "$t"
done
