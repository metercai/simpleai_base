import psutil
import torch
from enum import Enum

class CPUState(Enum):
    GPU = 0
    CPU = 1
    MPS = 2

cpu_state = CPUState.GPU

try:
    if torch.backends.mps.is_available():
        cpu_state = CPUState.MPS
        import torch.mps
except:
    pass

def is_nvidia():
    global cpu_state
    if cpu_state == CPUState.GPU:
        if torch.version.cuda:
            return True
    return False

def get_ram_and_gpu_info():
    ram_memory = psutil.virtual_memory().total
    swap_memory = psutil.swap_memory().total
    if is_nvidia():
        try:
            import pynvml
            pynvml_available = True
        except ImportError:
            pynvml_available = False
    else:
        pynvml_available = False
    
    gpu_info_list = []
    driver_version = ''
    cuda_version = ''
    if pynvml_available:
        pynvml.nvmlInit()
        driver_version = str(pynvml.nvmlSystemGetDriverVersion())
        cuda_version = str(pynvml.nvmlSystemGetCudaDriverVersion())
        device_count = pynvml.nvmlDeviceGetCount()
        for i in range(device_count):
            handle = pynvml.nvmlDeviceGetHandleByIndex(i)
            gpu_name = pynvml.nvmlDeviceGetName(handle)
            gpu_brand = gpu_name.split(' ')[0].strip()
            gpu_memory_info = pynvml.nvmlDeviceGetMemoryInfo(handle)
            gpu_memory_total = gpu_memory_info.total
            gpu_memory_free = gpu_memory_info.free
            gpu_info_list.append(gpu_brand)
            gpu_info_list.append(gpu_name)
            gpu_info_list.append(str(gpu_memory_total))
            gpu_info_list.append(str(gpu_memory_free))
        pynvml.nvmlShutdown()

    ram_and_gpu = [str(ram_memory), str(swap_memory), driver_version, cuda_version] + gpu_info_list
    return ','.join(ram_and_gpu)
