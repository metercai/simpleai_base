import subprocess
import os
import sys
import torch
import gc
import ldm_patched.modules.model_management as model_management
from . import comfyclient_pipeline

comfyd_process = None

def is_running():
    global comfyd_process
    if comfyd_process is None:
        return False
    process_code = comfyd_process.poll()
    if process_code is None:
        return True
    print("[Comfyd] comfyd process status code: {process_code}")
    return False

def start(args_patch=[[]]):
    global comfyd_process
    if not is_running():
        backend_script = os.path.join(os.getcwd(),'comfy/main.py')
        args_comfyd = [["--preview-method", "auto"], ["--port", "8187"], ["--disable-auto-launch"]]
        for patch in args_patch:
            found = False
            for i, sublist in enumerate(args_comfyd):
                if sublist[0] == patch[0]:
                    args_comfyd[i][1] = patch[1]
                    found = True
                    break
            if not found:
                args_comfyd.append(patch)
        arguments = [arg for sublist in args_comfyd for arg in sublist]
        process_env = os.environ.copy()
        process_env["PYTHONPATH"] = os.pathsep.join(sys.path)
        comfyd_process  = subprocess.Popen([sys.executable, backend_script] + arguments, env=process_env)
    comfyclient_pipeline.ws = None
    print("[Comfyd] Comfyd is running!")

def stop():
    global comfyd_process
    if is_running():
        comfyd_process.terminate()
        comfyd_process.wait()
    comfyd_process = None
    comfyclient_pipeline.ws = None
    model_management.unload_all_models()
    gc.collect()
    torch.cuda.empty_cache()
    print("[Comfyd] Comfyd stopped!")
