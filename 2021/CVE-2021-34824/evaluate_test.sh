#!/bin/bash

source istio_versions.sh

printf "checking gateways pods to see if they have TLS secrets loaded in memory...\n"
echo "If you see a secret called kubernetes://foo-dot-com that is ACTIVE then the gateway DOES have access to the K8s secret."
echo "If you see a secret called kubernetes://foo-dot-com that is WARMING then the gateway DOES NOT have access to the K8s secret."
printf "\n\n"

echo "listing secrets present in ns-a gateway-a"
./istioctl-${ISTIO_VERSION} proxy-config secrets $(kubectl get po -n ns-a -l app=istio-ingressgateway -oname | tail -n 1) -n ns-a

printf "\n\n"

echo "listing secrets present in ns-b gateway-b"
./istioctl-${ISTIO_VERSION} proxy-config secrets $(kubectl get po -n ns-b -l app=istio-ingressgateway -oname | tail -n 1) -n ns-b

printf "\n\n"
echo "----------------------------------------------------------------------------------------"

printf "\ntesting TLS connectivity to gateways...\n\n"

namespaces="a b"
for ns in ${namespaces}; do
  echo "trying to connect via TLS to ns-a gateway-${ns}"
  curl -s --resolve foo.com:443:$(kubectl get svc -n ns-${ns} gateway-${ns} -ojsonpath='{..ip}') https://foo.com -kf -o /dev/null
  result=$?

  if [ $result -eq 0 ]; then
    echo "The gateway in ns-${ns} IS terminating TLS!"
  else
    echo "The gateway in ns-${ns} IS NOT terminating TLS!"
  fi
done
