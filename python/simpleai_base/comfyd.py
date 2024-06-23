import subprocess
import os
import sys
import torch
import gc
import ldm_patched.modules.model_management as model_management
from . import comfyclient_pipeline

comfyd_process = None
echo_off = True
def is_running():
    global comfyd_process
    if 'comfyd_process' not in globals():
        return False
    if comfyd_process is None:
        return False
    process_code = comfyd_process.poll()
    if process_code is None:
        return True
    print("[Comfyd] comfyd process status code: {process_code}")
    return False

def start(args_patch=[[]]):
    global comfyd_process, echo_off
    if not is_running():
        backend_script = os.path.join(os.getcwd(),'comfy/main.py')
        args_comfyd = [["--preview-method", "auto"], ["--port", "8187"], ["--disable-auto-launch"]]
        for patch in args_patch:
            found = False
            for i, sublist in enumerate(args_comfyd):
                if sublist[0] == patch[0]:
                    if len(sublist)>1:
                        args_comfyd[i][1] = patch[1]
                    found = True
                    break
            if not found:
                args_comfyd.append(patch)
        if not echo_off:
            print(f'[Comfyd] args_comfyd was patched: {args_comfyd}, patch:{args_patch}')
        arguments = [arg for sublist in args_comfyd for arg in sublist]
        process_env = os.environ.copy()
        process_env["PYTHONPATH"] = os.pathsep.join(sys.path)
        if not echo_off:
            print(f'[Comfyd] Ready to start with arguments: {arguments}, env: {process_env}')
        if 'comfyd_process' not in globals():
            globals()['comfyd_process'] = None
        comfyd_process  = subprocess.Popen([sys.executable, backend_script] + arguments, env=process_env)
        comfyclient_pipeline.ws = None
    else:
        print("[Comfyd] Comfyd is running!")

def stop():
    global comfyd_process
    if 'comfyd_process' not in globals():
        return
    if comfyd_process is None:
        return
    if is_running():
        comfyd_process.terminate()
        comfyd_process.wait()
    del comfyd_process
    comfyclient_pipeline.ws = None
    model_management.unload_all_models()
    gc.collect()
    torch.cuda.empty_cache()
    print("[Comfyd] Comfyd stopped!")

def args_mapping(args_fooocus):
    args_comfy = []
    if "--gpu-device-id" in args_fooocus:
        args_comfy += [["--cuda-device", args_fooocus.index("--gpu-device-id")+1]]
    if "--async-cuda-allocation" in args_fooocus:
        args_comfy += [["--cuda-malloc"]]
    if "--vae-in-cpu" in args_fooocus:
        args_comfy += [["--vae-in-cpu"]]
    if "--directml" in args_fooocus:
        args_comfy += [["--directml"]]
    if "--disable-xformers" in args_fooocus:
        args_comfy += [["--disable-xformers"]]
    if "--always-cpu" in args_fooocus:
        args_comfy += [["--cpu"]]
    if "--always-low-vram" in args_fooocus:
        args_comfy += [["--lowvram"]]
    if "--always-gpu" in args_fooocus:
        args_comfy += [["--gpu-only"]]
    if not echo_off:
        print(f'[Comfyd] args_fooocus: {args_fooocus}\nargs_comfy: {args_comfy}')
    return args_comfy
