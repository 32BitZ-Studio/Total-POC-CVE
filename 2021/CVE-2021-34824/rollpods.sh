#!/bin/bash

kubectl rollout restart deploy gateway-a -n ns-a
kubectl rollout restart deploy gateway-b -n ns-b
kubectl rollout status deploy gateway-a -n ns-a
kubectl rollout status deploy gateway-b -n ns-b
