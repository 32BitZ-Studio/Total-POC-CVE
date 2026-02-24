#!/bin/bash

source istio_versions.sh
./istioctl-${ISTIO_VERSION} version
