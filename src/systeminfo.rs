use serde::{Deserialize, Serialize};
use pyo3::prelude::*;
use std::process::Command;
use std::env;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::Duration;
use crate::env_utils;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[pyclass]
pub struct SystemInfo {
    pub os_type: String,
    pub os_name: String,
    pub host_name: String,
    pub cpu_arch: String,
    pub cpu_brand: String,
    pub cpu_cores: u32,
    pub ram_total: u64,
    pub ram_free: u64,
    pub ram_swap: u64,
    pub gpu_brand: String,
    pub gpu_name: String,
    pub gpu_memory: u64,
    pub local_ip: String,
    pub local_port: u16,
    pub loopback_port: u16,
    pub mac_address: String,
    pub public_ip: String,
    pub location: String,
    pub disk_total: u64,
    pub disk_free: u64,
    pub disk_uuid: String,
    pub root_dir: String,
    pub exe_dir: String,
    pub exe_name: String,
    pub pyhash: String,
    pub uihash: String,
}


impl SystemInfo {

    pub fn generate() -> Self {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let system_info = rt.block_on(async {
            match tokio::time::timeout(Duration::from_secs(10), SystemInfo::_generate()).await {
                Ok(system_info) => system_info,
                Err(_) => {
                    SystemInfo::default()
                }
            }
        });
        system_info
    }
    async fn _generate() -> Self {
        let os_type = env::consts::OS.to_string();
        let (os_name, host_name) = get_os_info().await;
        let cpu_arch = env::consts::ARCH.to_string();
        let (cpu_brand, cpu_cores) = get_cpu_info().await;
        let (ram_total, ram_free, ram_swap) = get_ram_info().await;
        let (disk_total, disk_free, disk_uuid) = get_disk_info().await;
        let (gpu_brand, gpu_name, gpu_memory) = get_gpu_info().await;

        let root_dir = match env::current_dir() {
            Ok(dir) => dir,
            Err(e) => {
                tracing::error!("env::current_dir, error:{:?}", e);
                PathBuf::from("/") }
        };
        let exe_dir = match env::current_exe() {
            Ok(dir) => dir,
            Err(e) => {
                tracing::error!("env::current_exe, error:{:?}", e);
                PathBuf::from("/") }
        };
        let mut exe_name = "simpleai_base".to_string();
        if let Some(exe) = env::args().collect::<Vec<_>>().get(1).cloned() {
            exe_name = exe.to_string()
        }
        let local_ip = env_utils::get_ipaddr_from_stream(None).await.unwrap_or_else(|_| Ipv4Addr::new(0, 0, 0, 0));
        let public_ip = env_utils::get_ipaddr_from_public(false).await.unwrap().to_string();
        let local_port = env_utils::get_port_availability(local_ip.clone(), 8186).await;
        let loopback_port = env_utils::get_port_availability(Ipv4Addr::new(127,0,0,1), 8188).await;
        let location = env_utils::get_location().await.unwrap().to_string();
        let (pyhash, uihash) = env_utils::get_program_hash().await.unwrap_or_else(|_| ("0".to_string(), "0".to_string()));

        Self {
            os_type,
            os_name,
            host_name,
            cpu_arch,
            cpu_brand,
            cpu_cores,
            ram_total,
            ram_free,
            ram_swap,
            gpu_brand,
            gpu_name,
            gpu_memory,
            local_ip: local_ip.to_string(),
            local_port,
            loopback_port,
            mac_address: env_utils::get_mac_address(local_ip.into()).await,
            public_ip,
            location,
            disk_total,
            disk_free,
            disk_uuid,
            root_dir: root_dir.to_string_lossy().into_owned(),
            exe_dir: exe_dir.to_string_lossy().into_owned(),
            exe_name,
            pyhash,
            uihash,
        }
    }
}

#[pymethods]
impl SystemInfo {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or("Unknown".to_string())
    }
}

impl Default for SystemInfo {
    fn default() -> Self {
        Self {
            os_type: env::consts::OS.to_string(),
            os_name: "Unknown".to_string(),
            host_name: "Unknown".to_string(),
            cpu_arch: env::consts::ARCH.to_string(),
            cpu_brand: "Unknown".to_string(),
            cpu_cores: 0,
            ram_total: 0,
            ram_free: 0,
            ram_swap: 0,
            gpu_brand: "Unknown".to_string(),
            gpu_name: "Unknown".to_string(),
            gpu_memory: 0,
            local_ip: "0.0.0.0".to_string(),
            local_port: 8186,
            loopback_port: 8188,
            mac_address: "Unknown".to_string(),
            public_ip: "Unknown".to_string(),
            location: "CN".to_string(),
            disk_total: 0,
            disk_free: 0,
            disk_uuid: "Unknown".to_string(),
            root_dir: "Unknown".to_string(),
            exe_dir: "Unknown".to_string(),
            exe_name: "Unknown".to_string(),
            pyhash: "Unknown".to_string(),
            uihash: "Unknown".to_string(),
        }
    }
}
async fn get_os_info() -> (String, String) {
    match env::consts::OS {
        "windows" => {
            let os_version_str = run_command("powershell", &["(Get-CimInstance Win32_OperatingSystem).Name"]);
            let os_version = os_version_str.split('|').nth(0).unwrap().trim().to_string();
            let host_name = run_command("powershell", &["(Get-CimInstance Win32_ComputerSystem).Name"]).trim().to_string();
            println!("get_os_info is ok: {}, {}", os_version, host_name);
            (os_version, host_name)
        }
        "linux" => {
            let os_version_str = run_command("cat", &["/etc/os-release"]);
            let mut os_version = "".to_string();
            for line in os_version_str.lines() {
                if line.starts_with("NAME=") {
                    os_version = line.split('=').nth(1).unwrap().trim_matches(|c: char| c == '"' || c.is_whitespace()).to_string() + " ";
                }
                if line.starts_with("VERSION=") {
                    os_version += line.split('=').nth(1).unwrap().trim_matches(|c: char| c == '"' || c.is_whitespace());
                }
            }
            let host_name = run_command("hostname", &[]).trim().to_string();
            (os_version, host_name)
        }
        "macos" => {
            let os_version_str = run_command("sw_vers", &["-productVersion"]);
            let (os_version, _) = os_version_str.rsplit_once('.').unwrap();
            //let host_name = run_command("scutil", &["-n", "ComputerName"]);
            let host_name = run_command("hostname", &[]).trim().to_string();
            (os_version.to_string(), host_name)
        }
        _ => ("".to_string(), "".to_string()),
    }


}
async fn get_cpu_info() -> (String, u32) {
    match env::consts::OS {
        "windows" => {
            let cpu_brand = run_command("powershell", &["(Get-CimInstance Win32_Processor).Name"]).trim().to_string();
            let cpu_cores = run_command("powershell", &["(Get-CimInstance Win32_Processor).NumberOfLogicalProcessors"]).trim().parse::<u32>().unwrap();
            println!("get_cpu_info is ok: {}, {}", cpu_brand, cpu_cores);
            (cpu_brand, cpu_cores)
        },
        "linux" => {
            let cpu_info = run_command("lscpu", &[]);
            let mut cpu_brand = "".to_string();
            let mut cpu_cores = 0;
            for line in cpu_info.lines() {
                if line.starts_with("CPU(s):") {
                    cpu_cores = line.split(':').nth(1).unwrap().trim().parse::<u32>().unwrap();
                }
                if line.starts_with("Model name:") {
                    cpu_brand = line.split(':').nth(1).unwrap().trim().to_string();
                }
            }
            (cpu_brand, cpu_cores)
        },
        "macos" => {
            let cpu_brand = run_command("sysctl", &["-n", "machdep.cpu.brand_string"]).trim().to_string();
            let cpu_cores = run_command("sysctl", &["-n", "hw.ncpu"]).trim().parse::<u32>().unwrap();
            (cpu_brand, cpu_cores)
        },
        _ => ("".to_string(), 0)
    }
}

async fn get_ram_info() -> (u64, u64, u64) {
    match env::consts::OS {
        "windows" => {
            let total_ram = run_command("powershell", &["(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory"]).trim().parse::<u64>().unwrap();
            let swap_ram = run_command("powershell", &["(Get-CimInstance Win32_OperatingSystem).TotalVirtualMemorySize"]).trim().parse::<u64>().unwrap();
            let free_ram = run_command("powershell", &["(Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory"]).trim().parse::<u64>().unwrap();
            println!("get_ram_info is ok: {}, {}, {}", total_ram, swap_ram, free_ram);
            (total_ram, free_ram * 1024, swap_ram * 1024)
        },
        "linux" => {
            let ram_info = run_command("free", &[]);
            let parts: Vec<Vec<&str>> = ram_info
                .lines()
                .map(|line| {
                    line.split_whitespace()
                        .map(|part| { part.trim() })
                        .collect::<Vec<&str>>()
                }).collect();
            let total = parts.get(1).and_then(|row| row.get(1)).map(|value| value.to_string())
                .unwrap_or_else(|| "raminfo".to_string()).parse::<u64>().unwrap_or(0);
            let free = parts.get(1).and_then(|row| row.get(3)).map(|value| value.to_string())
                .unwrap_or_else(|| "raminfo".to_string()).parse::<u64>().unwrap_or(0);
            let swap = parts.get(2).and_then(|row| row.get(1)).map(|value| value.to_string())
                .unwrap_or_else(|| "raminfo".to_string()).parse::<u64>().unwrap_or(0);
            (total/1024, free/1024, swap/1024)
        },
        "macos" => {
            let ram_total = run_command("sysctl", &["-n", "hw.memsize"]).parse::<u64>().unwrap_or(0);
            let ram_free = run_command("sysctl", &["-n", "hw.usermem"]).parse::<u64>().unwrap_or(0);
            let ram_swap_pages = run_command("sysctl", &["-n", "vm.pages"]).parse::<u64>().unwrap_or(0);
            let ram_swap_pagesize = run_command("sysctl", &["-n", "vm.pagesize"]).parse::<u64>().unwrap_or(0);
            (ram_total, ram_free, ram_swap_pages * ram_swap_pagesize)
        },
        _ => (0, 0, 0)
    }
}

async fn get_disk_info() -> (u64, u64, String) {
    match env::consts::OS {
        "windows" => {
            let total = run_command("powershell", &["(Get-CimInstance Win32_LogicalDisk -Filter \"DeviceID='C:'\").Size"]).trim().parse::<u64>().unwrap_or(0);
            let free = run_command("powershell", &["(Get-CimInstance Win32_LogicalDisk -Filter \"DeviceID='C:'\").FreeSpace"]).trim().parse::<u64>().unwrap_or(0);
            let uuid = run_command("powershell", &["(Get-CimInstance Win32_LogicalDisk -Filter \"DeviceID='C:'\").VolumeSerialNumber"]).trim().to_string();
            println!("get_disk_info is ok: {}, {}, {}", total, free, uuid);
            (total, free, uuid)
        }
        "linux" => {
            let disk_info = run_command("df", &[]);
            let lines: Vec<Vec<&str>> = disk_info
                .lines()
                .map(|line| {
                    line.split_whitespace()
                        .map(|part| { part.trim() })
                        .collect::<Vec<&str>>()
                }).collect();
            let mut total = 0;
            let mut free = 0;
            let mut uuid = "".to_string();
            for line in lines {
                if line.get(5).unwrap().to_string() == "/" {
                    let sysdisk = line.get(0).unwrap().to_string();
                    total = line.get(1).unwrap().to_string().parse::<u64>().unwrap_or(0);
                    free = line.get(3).unwrap().to_string().parse::<u64>().unwrap_or(0);
                    let uuid_resault = run_command("blkid", &[&sysdisk]);
                    let uuid_str = uuid_resault.split_whitespace().nth(1).unwrap();
                    uuid = uuid_str[6..uuid_str.len()-1].to_string();
                }
            }
            (total/1024, free/1024, uuid)
        }
        "macos" => {
            let disk_info = run_command("df", &[]);
            let lines: Vec<Vec<&str>> = disk_info
                .lines()
                .map(|line| {
                    line.split_whitespace()
                        .map(|part| { part.trim() })
                        .collect::<Vec<&str>>()
                }).collect();
            let mut total = 0;
            let mut free = 0;
            let mut uuid = "".to_string();
            for line in lines {
                if line.get(8).unwrap().to_string() == "/" {
                    let sysdisk = line.get(0).unwrap().to_string();
                    total = line.get(1).unwrap().to_string().parse::<u64>().unwrap_or(0);
                    free = line.get(3).unwrap().to_string().parse::<u64>().unwrap_or(0);
                    let sysdiskinfo = run_command("diskutil", &["info", &sysdisk]);
                    let parts: Vec<Vec<&str>> = sysdiskinfo
                        .lines()
                        .map(|line| {
                            line.split(':')
                                .map(|part| { part.trim() })
                                .collect::<Vec<&str>>()
                        }).collect();
                    for line in parts {
                        if let (Some(key), Some(value)) = (line.get(0), line.get(1))  {
                            if *key == "Volume UUID" {
                                uuid = value.to_string();
                            }
                        }
                    }
                }
            }
            (total/2, free/2, uuid)
        }
        _ => (0, 0, "".to_string())
    }
}

async fn get_gpu_info() -> (String, String, u64){
    match env::consts::OS {
        "windows" => {
            let mut gpu_name = "reserve".to_string();
            let mut gpu_memory = 0;
            let mut gpu_brand = run_command("powershell", &["(Get-CimInstance Win32_VideoController -Filter \"Name like '%NVIDIA%'\").Name"]).trim().to_string();
            if gpu_brand.is_empty() {
                gpu_brand = run_command("powershell", &["(Get-CimInstance Win32_VideoController -Filter \"Name like '%AMD%'\").Name"]).trim().to_string();
                if gpu_brand.is_empty() {
                    gpu_brand = "Unknown".to_string();
                } else {
                    gpu_name = gpu_brand;
                    gpu_brand = "AMD".to_string();
                    gpu_memory = run_command("powershell", &["(Get-CimInstance Win32_VideoController -Filter \"Name like '%AMD%'\").AdapterRAM"]).trim().parse::<u64>().unwrap_or(0);
                }
            } else {
                gpu_name = gpu_brand;
                gpu_brand = "NVIDIA".to_string();
                let gpu_info = run_command("nvidia-smi", &["--query-gpu=name,memory.total,memory.free", "--format=csv"]);
                let parts: Vec<Vec<&str>> = gpu_info
                    .lines()
                    .map(|line| {
                        line.split(',')
                            .map(|part| { part.trim() })
                            .collect::<Vec<&str>>()
                    }).collect();
                let gpu_memory_str = parts.get(1).and_then(|row| row.get(1)).map(|value| value.to_string())
                    .unwrap_or_else(|| "".to_string());
                gpu_memory = gpu_memory_str.split_whitespace().nth(0).unwrap().parse::<u64>().unwrap_or(0);
            }
            println!("get_gpu_info is ok: {}, {}, {}", gpu_brand, gpu_name, gpu_memory);
            (gpu_brand, gpu_name, gpu_memory)
        }

        "linux" => {
            let mut gpu_name = "reserve".to_string();
            let mut gpu_memory = 0;
            let mut gpu_brand = run_command("sh", &["-c", "lspci | grep VGA | grep NVIDIA"]);
            if gpu_brand.is_empty() {
                gpu_brand = run_command("sh", &["-c", "lspci | grep VGA | grep -E AMD|ATI"]);
                if gpu_brand.is_empty() {
                    gpu_brand = "Unknown".to_string();
                } else {
                    gpu_brand = "AMD".to_string();
                }
            } else {
                gpu_brand = "NVIDIA".to_string();
                let gpu_info = run_command("nvidia-smi", &["--query-gpu=name,memory.total,memory.free", "--format=csv"]);
                let parts: Vec<Vec<&str>> = gpu_info
                    .lines()
                    .map(|line| {
                        line.split(',')
                            .map(|part| { part.trim() })
                            .collect::<Vec<&str>>()
                    }).collect();
                gpu_name = parts.get(1).and_then(|row| row.get(0)).map(|value| value.to_string())
                    .unwrap_or_else(|| "".to_string());
                let gpu_memory_str = parts.get(1).and_then(|row| row.get(1)).map(|value| value.to_string())
                    .unwrap_or_else(|| "".to_string());
                gpu_memory = gpu_memory_str.split_whitespace().nth(0).unwrap().parse::<u64>().unwrap_or(0);
            }
            (gpu_brand, gpu_name, gpu_memory)
        }
        "macos" => {
            ("Apple".to_string(), "reserve".to_string(), 0)
        }
        _ => {("Unknown".to_string(), "reserve".to_string(), 0)}
    }
}


fn run_command(command: &str, args: &[&str]) -> String {
    match Command::new(command).args(args).output() {
        Ok(output) => {
            if output.status.success() && !output.stdout.is_empty() {
                String::from_utf8_lossy(&output.stdout).into_owned()
            } else {
                "".to_string()
            }
        }
        Err(_) => "".to_string(),
    }
}
