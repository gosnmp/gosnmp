#!/bin/bash

for t in `grep 'func Test' *.go | awk '{print $2}' | awk -F\( '{print $1}' | grep -v Verax` ; do
	echo $t
	go test -run $t
done
