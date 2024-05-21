import subprocess
import os
import sys

comfyd_process = None

def is_running():
    if comfyd_process is not None and comfyd_process.poll() is None:
        return True
    return False

def start(args_patch):
    global comfyd_process
    if comfyd_process is None:
        backend_script = os.path.join(os.getcwd(),'comfy/main.py')
        args_comfyd = [["--preview-method", "auto"], ["--port", "8188"], ["--disable-auto-launch"]]
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
        comfyd_process  = subprocess.Popen([sys.executable, backend_script] + arguments)

def stop():
    global comfyd_process
    if comfyd_process is not None:
        comfyd_process.terminate()
        comfyd_process.wait()
        comfyd_process = None
