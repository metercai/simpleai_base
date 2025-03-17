import time
import json
from simpleai_base import simpleai_base
print("Checking ...")
token = simpleai_base.init_local('SimpleSDXL')
upstream_did = token.get_p2p_upstream_did()
print(f'upstream_did={upstream_did}')
sysinfo = json.loads(token.get_sysinfo().to_json())
sysinfo.update(dict(did=token.get_sys_did()))
print(f'GPU: {sysinfo["gpu_name"]}, RAM: {sysinfo["ram_total"]}MB, SWAP: {sysinfo["ram_swap"]}MB, VRAM: {sysinfo["gpu_memory"]}MB, DiskFree: {sysinfo["disk_free"]}MB, CUDA: {sysinfo["cuda"]}')

guest_did = token.get_guest_did()
print(f'guest_did:{guest_did}')
guest_cert = token.get_register_cert(guest_did)
print(f'guest_cert:{guest_cert}')
while True:
    time.sleep(1)
