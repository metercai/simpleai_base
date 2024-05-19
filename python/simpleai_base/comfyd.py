import subprocess
import os
import sys

backend_script = os.path.join(os.getcwd(),'comfy/main.py')
arguments = ["--preview-method", "auto", "--port", "8188", "--disable-auto-launch"]
comfyd_process  = subprocess.Popen([sys.executable, backend_script] + arguments)
