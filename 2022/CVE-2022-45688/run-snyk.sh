#!/bin/sh

root=$(pwd)
snyk_report=scan-results/snyk/snyk-report.json;

if [ -f "${snyk_report}" ]; then
  echo "${snyk_report} exists, skipping analysis";
else
  echo "running snyk analysis on ${e}" ;
  snyk test --json --json-file-output=${snyk_report};
fi


