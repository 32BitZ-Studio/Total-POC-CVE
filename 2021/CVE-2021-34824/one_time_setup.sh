#!/bin/bash

#downloads all the binaries needed to repro

source istio_versions.sh

if [ $(uname -s) == "Darwin" ]; then
  ISTIO_OS="osx"
  MKCERT_OS="darwin"
elif [ $(uname -s) == "Linux" ]; then
  ISTIO_OS="linux"
  MKCERT_OS="linux"
else
  echo "Cannot find supported OS, bailing."
  exit 1
fi
  
if [ $(uname -m) == "x86_64" ]; then
  if [ ${ISTIO_OS} == "osx" ]; then
    ISTIO_ARCH=""
  elif [ ${ISTIO_OS} == "linux" ]; then
    ISTIO_ARCH="-amd64"
  fi
  MKCERT_ARCH="-amd64"
elif [ $(uname -m) == "arm64" ]; then
  ISTIO_ARCH="-arm64"
  MKCERT_ARCH="-arm64"
else
  echo "Cannot find supported architecture, bailing."
  exit 1
fi

echo "Downloading mkcert..."
curl -sLO https://github.com/FiloSottile/mkcert/releases/download/v1.4.4/mkcert-v1.4.4-${MKCERT_OS}${MKCERT_ARCH}
echo "Downloading istioctl..."
curl -sLO https://github.com/istio/istio/releases/download/${ISTIO_VULN}/istioctl-${ISTIO_VULN}-${ISTIO_OS}${ISTIO_ARCH}.tar.gz
curl -sLO https://github.com/istio/istio/releases/download/${ISTIO_SAFE}/istioctl-${ISTIO_SAFE}-${ISTIO_OS}${ISTIO_ARCH}.tar.gz

echo "setting up mkcert"
mv mkcert-v1.4.4-${MKCERT_OS}${MKCERT_ARCH} mkcert
chmod +x ./mkcert

echo "setting up istioctl"
tar zxvf istioctl-${ISTIO_VULN}-${ISTIO_OS}${ISTIO_ARCH}.tar.gz
mv istioctl istioctl-${ISTIO_VULN}

tar zxvf istioctl-${ISTIO_SAFE}-${ISTIO_OS}${ISTIO_ARCH}.tar.gz
mv istioctl istioctl-${ISTIO_SAFE}
