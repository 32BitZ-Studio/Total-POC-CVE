set -ex

USERNAME=cashwilliams
IMAGE=cve-2019-14287-demo

docker build -t $USERNAME/$IMAGE:latest .
