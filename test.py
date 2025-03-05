import time
import json
from simpleai_base import simpleai_base
print("Checking ...")
token = simpleai_base.init_local('SimpleSDXL')
sysinfo = json.loads(token.get_sysinfo().to_json())
sysinfo.update(dict(did=token.get_sys_did()))
print(f'GPU: {sysinfo["gpu_name"]}, RAM: {sysinfo["ram_total"]}MB, SWAP: {sysinfo["ram_swap"]}MB, VRAM: {sysinfo["gpu_memory"]}MB, DiskFree: {sysinfo["disk_free"]}MB, CUDA: {sysinfo["cuda"]}')

while True:
    time.sleep(1)
