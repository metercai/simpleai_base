import psutil
from enum import Enum

def get_ram_and_nvidia_gpu_info():
    ram_memory = psutil.virtual_memory().total
    swap_memory = psutil.swap_memory().total
    try:
        import pynvml
        pynvml_available = True
    except ImportError:
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
