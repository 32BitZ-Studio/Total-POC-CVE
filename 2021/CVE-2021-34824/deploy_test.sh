#!/bin/bash

source istio_versions.sh

echo "creating namespaces ns-a and ns-b..."
kubectl apply -f manifests/ns.yaml

echo "deploying istio ${ISTIO_VERSION}"
./istioctl-${ISTIO_VERSION} install -yf manifests/istio-profile.yaml

echo "generating a self signed cert"
./mkcert -cert-file foo.com.crt -key-file foo.com.key foo.com

echo "installing the self signed cert into ns-a ONLY!"
kubectl create secret tls foo-dot-com --key=foo.com.key --cert=foo.com.crt --dry-run=client -oyaml -n ns-a > manifests/a/cert.yaml

echo "deploy test apps into ns-a"
kubectl apply -f manifests/a/

echo "deploy test apps into ns-b"
kubectl apply -f manifests/b/

namespaces="a b"
for ns in ${namespaces}; do
  echo "waiting for gateway-${ns} loadbalancer to become ready"
  max_retries=10
  current_try=0
  while true; do
    if [[ "${current_try}" -gt "${max_retries}" ]]; then
      echo "max retries exceeded while waiting for gateway-${ns} load balancer to obtain an IP, bailing."
      exit 1
    fi
    ip=$(kubectl get svc gateway-${ns} -n ns-${ns} -ojsonpath='{..ip}')
    if [[ ${ip} != "" ]]; then
      echo "load balancer for gateway-${ns} is ready"
      break
    else
      current_try=$((current_try+1))
      sleep 3
    fi
  done
done
