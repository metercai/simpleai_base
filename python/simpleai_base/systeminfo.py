

def get_ram_and_gpu_info():
    import psutil
    ram_memory = psutil.virtual_memory().total
    swap_memory = psutil.swap_memory().total
    try:
        import pynvml
        pynvml_available = True
    except ImportError:
        pynvml_available = False
    gpu_info_list = []
    if pynvml_available:
        pynvml.nvmlInit()
        device_count = pynvml.nvmlDeviceGetCount()
        for i in range(device_count):
            handle = pynvml.nvmlDeviceGetHandleByIndex(i)
            gpu_name = pynvml.nvmlDeviceGetName(handle).decode('utf-8')
            gpu_brand = gpu_name.split(' ')[0].strip()
            gpu_memory_info = pynvml.nvmlDeviceGetMemoryInfo(handle)
            gpu_memory_total = gpu_memory_info.total
            gpu_memory_free = gpu_memory_info.free
            driver_version = pynvml.nvmlSystemGetDriverVersion().decode('utf-8')
            cuda_version = pynvml.nvmlSystemGetCudaDriverVersion()
            gpu_info = {
                "gpu_brand": gpu_brand,
                "gpu_name": gpu_name,
                "gpu_memory": gpu_memory_total,
                "gpu_free": gpu_memory_free,
                "driver": driver_version,
                "cuda": cuda_version
            }
            gpu_info_list.append(gpu_info)
        pynvml.nvmlShutdown()

    return {
        "ram_total": ram_memory,
        "ram_swap": swap_memory,
        "gpu_info": gpu_info_list
    }
