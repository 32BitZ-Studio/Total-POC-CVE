#!/bin/bash

# check if an IP address is provided ass an argument
if [ -z "$1" ]
then
  echo "Usage: $0 <IP address>"
  exit 1
fi

# set the IP address from the CLI
ip="$1"

# create a folder with the IP address as the name
mkdir -p "${ip}"

while true
do
  # change current directory to IP folder
  cd "${ip}"
  # Use curl to download the image capture from the camera and save it with the current date and time as the filename
  filename="$(date +%Y-%m-%d_%H-%M-%S).png"
  curl "http://${ip}:9989" -o "${filename}"
  
# wait for 2 seconds before downloading the next image
  sleep 2
done
