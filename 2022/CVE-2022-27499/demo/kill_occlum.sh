#!/bin/bash

# get pid
occlum_pid=$(ps -ef | grep occlum-run | grep -v grep | awk '{print $2}')

echo $occlum_pid

if [ ! -n "$occlum_pid" ]; then
  echo "PID IS NULL!"
else
  kill $occlum_pid
fi
