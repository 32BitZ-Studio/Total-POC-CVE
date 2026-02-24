#!/bin/bash
#
# CVE-2017-9841 detector Ver. 0.2
# by Massimiliano Brasile
#

# rif. https://www.cvedetails.com/cve/CVE-2017-9841/
# rif. https://github.com/PrestaShop/PrestaShop/issues/17059#issuecomment-572114133
check_ver() {
  v=0
  for k in $(echo $1 | tr "." "\n")
  do
    v=$(($v*256 + $k))
  done
  if [ "$v" -ge 460051 ] && [ "$v" -lt 524288 ]; then # 7.5.19 -> 460051 | 8.0.0 -> 524288
    return 1
  fi
  if [ "$v" -ge 525569 ]; then # 8.5.1-> 525569
    return 1
  fi
  return 0
}

echo "CVE-2017-9841 detector Ver. 0.2 - Massimiliano Brasile"
echo
echo "scanning.."
for i in `find . -type d -regex ".*phpunit/phpunit"`
do
  for j in `find "$i" -type f -name "Version.php"`
  do
    VER=`cat $j|grep new|grep Version|sed -n "s/^.*'\(.*\)'.*$/\1/ p"`
  done
  check_ver "$VER"
  if [ $? -eq 1 ]; then
    echo "[$VER] $i | Safe"
  else
    echo "[$VER] $i | CVE-2017-9841 detected!!"
  fi
done

