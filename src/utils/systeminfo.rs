use serde::{Deserialize, Serialize};
use pyo3::prelude::*;
use std::process::Command;
use std::env;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::fs;
use std::time::UNIX_EPOCH;
use base58::ToBase58;

use sysinfo::System;
use tracing::debug;

use crate::dids::token_utils;
use crate::utils::env_utils;


#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SystemBaseInfo {
    pub os_type: String,
    pub os_name: String,
    pub host_type: String,
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
    pub driver: String,
    pub cuda: String,
    pub disk_total: u64,
    pub disk_free: u64,
    pub disk_uuid: String,
    pub root_dir: String,
    pub root_name: String,
    pub exe_dir: String,
    pub exe_name: String,
    pub os_time: u64,
    pub root_time: u64,
}

impl SystemBaseInfo {
    pub fn generate() -> Self {
        let (disk_total, disk_free, disk_uuid) = get_disk_info();
        let (mut gpu_brand, mut gpu_name, mut gpu_memory, mut driver, mut cuda) = get_gpu_info();
        //println!("get_disk_info and get_gpu_info: {}, {}, {}, {}, {}, {}, {}, {}", disk_total, disk_free, disk_uuid, gpu_brand, gpu_name, gpu_memory, driver, cuda);
        if gpu_brand=="NVIDIA" {
            let ram_gpu_info = env_utils::get_ram_and_nvidia_gpu_info();
            if ram_gpu_info!="Unknown" {
                let parts: Vec<&str> = ram_gpu_info.split(',').collect();
                if parts.len()>=4 {
                    driver = parts[2].to_string();
                    cuda = parts[3].to_string();
                }
                if parts.len()>=8 {
                    gpu_brand = parts[4].to_string();
                    gpu_name = parts[5].to_string();
                    gpu_memory = parts[6].parse::<u64>().unwrap_or(0);
                }
            } 
        }

        let host_type = is_virtual_or_docker_or_physics();

        let mut sys = System::new_all();
        sys.refresh_all();
        let os_type = env::consts::OS.to_string();
        let os_name = format!("{} {}", System::name().unwrap_or("Unknown".to_string()), System::os_version().unwrap_or("Unknown".to_string()));
        let host_name = System::host_name().unwrap_or("Unknown".to_string());
        let cpu_arch = env::consts::ARCH.to_string();
        let (cpu_brand, cpu_cores) = (sys.cpus()[0].brand(), sys.physical_core_count());
        let (ram_total, ram_free, ram_swap) = (sys.total_memory(), sys.available_memory(), sys.total_swap());

        let root_dir = std::env::args()
            .nth(1)
            .and_then(|arg| {
                let path = PathBuf::from(&arg);
                let abs_path = if path.is_absolute() {
                    path
                } else {
                    env::current_dir()
                        .ok()?
                        .join(&path)
                };

                match fs::metadata(&abs_path) {
                    Ok(metadata) => {
                        if metadata.is_file() {
                            tracing::info!("输入为文件路径，提取所在目录");
                            abs_path.parent().map(|p| p.to_path_buf())
                        } else {
                            Some(abs_path)
                        }
                    }
                    Err(e) => {
                        tracing::error!("路径访问错误: {:?}", e);
                        None
                    }
                }
            })
            .and_then(|p| {
                if p.exists() {
                    p.canonicalize().ok()
                } else {
                    tracing::error!("路径不存在: {:?}", p);
                    None
                }
            })
            .unwrap_or_else(|| {
                tracing::warn!("使用默认根目录");
                PathBuf::from("/")
            });

        let root_name = Path::new(&root_dir)
            .file_name()
            .and_then(|f| f.to_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "root".to_string());

        let exe_dir = env::current_exe().unwrap_or_else(|e| {
            tracing::error!("env::current_exe, error:{:?}", e);
            PathBuf::from("/")
        });

        let exe_name = env::args().nth(1).unwrap_or_else(|| "SimpleAI".to_string());
        let os_sys_path = match env::consts::OS {
            "windows" => "C:\\Windows\\System32\\",
            "linux" => "/bin/",
            "macos" => "/bin/",
            _ => "",
        };
        let os_time = find_oldest_file(os_sys_path);
        let root_time = find_oldest_file(root_dir.to_str().unwrap());
        
        Self {
            os_type,
            os_name: os_name,
            host_type,
            host_name,
            cpu_arch,
            cpu_brand: cpu_brand.to_string(),
            cpu_cores: cpu_cores.unwrap_or(0) as u32,
            ram_total: ram_total/(1024*1024),
            ram_free: ram_free/(1024*1024),
            ram_swap: ram_swap/(1024*1024),
            gpu_brand,
            gpu_name,
            gpu_memory,
            driver,
            cuda,
            disk_total,
            disk_free,
            disk_uuid,
            root_dir: root_dir.to_string_lossy().into_owned(),
            root_name,
            exe_dir: exe_dir.to_string_lossy().into_owned(),
            exe_name,
            os_time,
            root_time
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[pyclass]
pub struct SystemInfo {
    pub os_type: String,
    pub os_name: String,
    pub host_type: String,
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
    pub driver: String,
    pub cuda: String,
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
    pub root_name: String,
    pub exe_dir: String,
    pub exe_name: String,
    pub pyhash: String,
    pub uihash: String,
    pub os_time: u64,
    pub root_time: u64,
}


impl SystemInfo {
    pub fn from_base(base: SystemBaseInfo) -> Self {
        Self {
            os_type: base.os_type,
            os_name: base.os_name,
            host_type: base.host_type,
            host_name: base.host_name,
            cpu_arch: base.cpu_arch,
            cpu_brand: base.cpu_brand,
            cpu_cores: base.cpu_cores,
            ram_total: base.ram_total,
            ram_free: base.ram_free,
            ram_swap: base.ram_swap,
            gpu_brand: base.gpu_brand,
            gpu_name: base.gpu_name,
            gpu_memory: base.gpu_memory,
            driver: base.driver,
            cuda: base.cuda,
            local_ip: "127.0.0.1".to_string(),
            local_port: 8186,
            loopback_port: 8187,
            mac_address: "Unknown".to_string(),
            public_ip: "0.0.0.0".to_string(),
            location: "CN".to_string(),
            disk_total: base.disk_total,
            disk_free: base.disk_free,
            disk_uuid: base.disk_uuid,
            root_dir: base.root_dir,
            root_name: base.root_name,
            exe_dir: base.exe_dir,
            exe_name: base.exe_name,
            pyhash: "Unknown".to_string(),
            uihash: "Unknown".to_string(),
            os_time: base.os_time,
            root_time: base.root_time,
        }
    }
    pub async fn generate() -> SystemInfo {
        let local_ip = env_utils::get_ipaddr_from_stream(None).await.unwrap_or_else(|_| Ipv4Addr::new(127, 0, 0, 1));
        let public_ip_task = env_utils::get_ipaddr_from_public(false);
        let local_port_task = env_utils::get_port_availability(local_ip.clone(), 8186);
        let loopback_port_task = env_utils::get_port_availability(Ipv4Addr::new(127, 0, 0, 1), 8187);
        let location_task = env_utils::get_location();
        let program_hash_task = env_utils::get_program_hash();
        let mac_address_task = env_utils::get_mac_address(local_ip.into());
        let (public_ip, local_port, loopback_port, location, program_hash, mac_address) =
            tokio::join!(public_ip_task, local_port_task, loopback_port_task, location_task, program_hash_task, mac_address_task);
        let (pyhash, uihash) = program_hash.unwrap_or_else(|_| ("Unknown".to_string(), "Unknown".to_string()));

        let sys_base_info = token_utils::SYSTEM_BASE_INFO.clone();

        let mut sysinfo = SystemInfo::from_base(sys_base_info);
        sysinfo.local_ip = local_ip.to_string();
        sysinfo.local_port = local_port;
        sysinfo.loopback_port = loopback_port;
        sysinfo.mac_address = mac_address;
        sysinfo.public_ip = public_ip.unwrap_or(Ipv4Addr::new(0, 0, 0, 0)).to_string();
        sysinfo.location = location;
        sysinfo.pyhash = pyhash;
        sysinfo.uihash = uihash;

        debug!("sysinfo is finished");
        sysinfo
    }
}

#[pymethods]
impl SystemInfo {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or("Unknown".to_string())
    }
}

fn get_disk_info() -> (u64, u64, String) {
    let (total, free, uuid) = match env::consts::OS {
        "windows" => {
            let total_str = run_command("powershell", &["(Get-CimInstance Win32_LogicalDisk -Filter \"DeviceID='C:'\").Size"]);
            let total_filtered = total_str.chars().filter(|c| c.is_ascii()).collect::<String>();
            let total = total_filtered.trim().parse::<u64>().unwrap_or(0);
            
            let free_str = run_command("powershell", &["(Get-CimInstance Win32_LogicalDisk -Filter \"DeviceID='C:'\").FreeSpace"]);
            let free_filtered = free_str.chars().filter(|c| c.is_ascii()).collect::<String>();
            let free = free_filtered.trim().parse::<u64>().unwrap_or(0);
            
            let mut uuid = run_command("powershell", &["(Get-CimInstance Win32_LogicalDisk -Filter \"DeviceID='C:'\").VolumeSerialNumber"])
                .chars().filter(|c| c.is_ascii()).collect::<String>().trim().to_string();
            //println!("get_disk_info is ok: {}:{}, {}:{}, {}", total_str,total, free_str,free, uuid);
            if uuid.is_empty() {
                uuid = run_command("cmd", &["/c", "vol", "c:"]).trim().to_string();
                if uuid.contains("卷的序列号是") || uuid.contains("Volume Serial Number is") {
                    let parts: Vec<&str> = uuid.split_whitespace().collect();
                    uuid = parts.last().unwrap_or(&"").to_string()
                }
            }
            if  uuid.is_empty() {
                let env_uuid_str = run_command("cmd", &["/c", "echo", "%COMPUTERNAME%-%SYSTEMDRIVE%"]).trim().to_string();
                uuid = token_utils::calc_sha256(&env_uuid_str.as_bytes()).to_base58();
            }
            //println!("get_disk_info is ok: {}, {}, {}", total, free, uuid);
            (total/(1024*1024), free/(1024*1024), uuid)
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
                    let uuid_resault = run_command("/usr/bin/lsblk", &["-f", "-P", &sysdisk]);
                    let uuid_str = uuid_resault.split_whitespace().nth(3).unwrap_or(&sysdisk);
                    if uuid_str.starts_with("UUID=") {
                        uuid = uuid_str[6..uuid_str.len()-1].to_string();
                    }
                    else { uuid = uuid_str.to_string();  }
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
                if line.len()>8 && line.get(8).unwrap().to_string() == "/" {
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
            (total/(2*1024), free/(2*1024), uuid)
        }
        _ => (0, 0, "".to_string())
    };
    //print!("get_disk_info.");
    (total, free, uuid)
}

fn get_gpu_info() -> (String, String, u64, String, String){
    let (gpu_brand, gpu_name, gpu_memory, driver, cuda) = match env::consts::OS {
        "windows" => {
            let mut driver = "reserve".to_string();
            let mut cuda = "-".to_string();
            let mut gpu_name = "reserve".to_string();
            let mut gpu_memory = 0;
            let mut gpu_brand = run_command("powershell", &["(Get-CimInstance Win32_VideoController -Filter \"Name like '%NVIDIA%'\").Name"]);
            gpu_brand = String::from_utf8_lossy(gpu_brand.trim().as_bytes()).to_string();
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
                let gpu_info0 = run_command("nvidia-smi", &["-q", "--display=MEMORY"]);
                let gpu_info = gpu_info0.chars().filter(|c| c.is_ascii()).collect::<String>();
                //println!("gpu_info is: {}, {}", gpu_info0, gpu_info);
                let parts: Vec<(&str, &str)> = gpu_info
                    .lines()
                    .filter_map(|line| {
                        line.split_once(':').map(|(key, value)| (key.trim(), value.trim()))
                    })
                    .collect();

                for (key, value) in &parts {
                    if *key == "Driver Version" {
                        driver = value.parse().unwrap_or_else(|_| "Unknown".to_string());
                    }
                    if *key == "CUDA Version" {
                        cuda = value.parse().unwrap_or_else(|_| "Unknown".to_string());
                    }
                    if *key == "Total" {
                        gpu_memory = value.split_whitespace().next().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
                        break;
                    }
                }
            }
            (gpu_brand, gpu_name, gpu_memory, driver, cuda)
        }

        "linux" => {
            let mut driver = "reserve".to_string();
            let mut cuda = "-".to_string();
            let mut gpu_name = "reserve".to_string();
            let mut gpu_memory = 0;
            let mut gpu_brand = run_command("sh", &["-c", "lspci | grep VGA | grep NVIDIA"]);
            if gpu_brand.is_empty() {
                gpu_brand = run_command("sh", &["-c", "lspci | grep VGA | grep AMD"]);
                if gpu_brand.is_empty() {
                    gpu_brand = "Unknown".to_string();
                } else {
                    gpu_brand = "AMD".to_string();
                    let gpu_info = run_command("rocm-smi", &["--showproductname", "--csv"]);
                    let parts: Vec<Vec<&str>> = gpu_info
                        .lines()
                        .map(|line| {
                            line.split(',')
                                .map(|part| { part.trim() })
                                .collect::<Vec<&str>>()
                        }).collect();
                    gpu_name = parts.get(1).and_then(|row| row.get(1)).map(|value| value.to_string())
                        .unwrap_or_else(|| "".to_string());
                    let gpu_version = parts.get(1).and_then(|row| row.get(9)).map(|value| value.to_string())
                        .unwrap_or_else(|| "".to_string());
                    gpu_name = gpu_name + "," + &gpu_version;
                    let gpu_info2 = run_command("rocm-smi", &["--showmeminfo vram", "--csv"]);
                    let parts2: Vec<Vec<&str>> = gpu_info2
                        .lines()
                        .map(|line| {
                            line.split(',')
                                .map(|part| { part.trim() })
                                .collect::<Vec<&str>>()
                        }).collect();
                    gpu_memory = parts2.get(1).and_then(|row| row.get(1)).map(|value| value.to_string())
                        .unwrap_or_else(|| "".to_string()).parse::<u64>().unwrap_or(0)/(1024*1024);
                }
            } else {
                gpu_brand = "NVIDIA".to_string();
                let gpu_name_str = run_command("nvidia-smi", &["--query-gpu=name", "--format=csv,noheader"]);
                gpu_name = gpu_name_str.lines().nth(0).map(|s| s.trim().to_string()).unwrap_or("Unknown".to_string());
                let gpu_info = run_command("nvidia-smi", &["-q", "--display=MEMORY"]);
                let parts: Vec<(&str, &str)> = gpu_info
                    .lines()
                    .filter_map(|line| {
                        line.split_once(':').map(|(key, value)| (key.trim(), value.trim()))
                    })
                    .collect();

                for (key, value) in &parts {
                    if *key == "Driver Version" {
                        driver = value.parse().unwrap()
                    }
                    if *key == "CUDA Version" {
                        cuda = value.parse().unwrap()
                    }
                    if *key == "Total" {
                        gpu_memory = value.split_whitespace().nth(0).unwrap_or("0").parse::<u64>().unwrap_or(0);
                        break;
                    }
                }
            }
            (gpu_brand, gpu_name, gpu_memory, driver, cuda)
        }
        "macos" => {
            let mut driver = "reserve".to_string();
            let mut cuda = "-".to_string();
            let mut gpu_brand = "Apple".to_string();
            let mut gpu_name = "reserve".to_string();
            let mut gpu_memory = 0;
            
            // 使用system_profiler获取GPU信息
            let gpu_info = run_command("system_profiler", &["SPDisplaysDataType", "-json"]);
            
            if !gpu_info.is_empty() {
                // 尝试解析JSON输出
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&gpu_info) {
                    if let Some(displays) = json.get("SPDisplaysDataType").and_then(|v| v.as_array()) {
                        if let Some(display) = displays.first() {
                            // 获取GPU型号
                            if let Some(model) = display.get("sppci_model").and_then(|v| v.as_str()) {
                                gpu_name = model.to_string();
                                
                                // 判断GPU品牌
                                if model.contains("AMD") || model.contains("ATI") {
                                    gpu_brand = "AMD".to_string();
                                } else if model.contains("NVIDIA") {
                                    gpu_brand = "NVIDIA".to_string();
                                } else if model.contains("Intel") {
                                    gpu_brand = "Intel".to_string();
                                }
                            }
                            
                            // 获取GPU内存
                            if let Some(vram) = display.get("spdisplays_vram_shared") {
                                if let Some(vram_str) = vram.as_str() {
                                    // 解析如 "1536 MB" 格式的内存大小
                                    if let Some(mb_str) = vram_str.split_whitespace().next() {
                                        if let Ok(mb) = mb_str.parse::<u64>() {
                                            gpu_memory = mb;
                                        }
                                    }
                                } else if let Some(vram_mb) = vram.as_u64() {
                                    gpu_memory = vram_mb;
                                }
                            }
                            
                            // 如果没有找到共享内存信息，尝试查找专用内存
                            if gpu_memory == 0 {
                                if let Some(vram) = display.get("spdisplays_vram") {
                                    if let Some(vram_str) = vram.as_str() {
                                        if let Some(mb_str) = vram_str.split_whitespace().next() {
                                            if let Ok(mb) = mb_str.parse::<u64>() {
                                                gpu_memory = mb;
                                            }
                                        }
                                    } else if let Some(vram_mb) = vram.as_u64() {
                                        gpu_memory = vram_mb;
                                    }
                                }
                            }
                        }
                    }
                } else {
                    // 如果JSON解析失败，尝试使用文本解析
                    let text_info = run_command("system_profiler", &["SPDisplaysDataType"]);
                    for line in text_info.lines() {
                        let line = line.trim();
                        if line.starts_with("Chipset Model:") {
                            gpu_name = line.split(':').nth(1).unwrap_or("").trim().to_string();
                            
                            if gpu_name.contains("AMD") || gpu_name.contains("ATI") {
                                gpu_brand = "AMD".to_string();
                            } else if gpu_name.contains("NVIDIA") {
                                gpu_brand = "NVIDIA".to_string();
                            } else if gpu_name.contains("Intel") {
                                gpu_brand = "Intel".to_string();
                            }
                        } else if line.contains("VRAM") {
                            if let Some(vram_part) = line.split(':').nth(1) {
                                if let Some(mb_str) = vram_part.trim().split_whitespace().next() {
                                    if let Ok(mb) = mb_str.parse::<u64>() {
                                        gpu_memory = mb;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            (gpu_brand, gpu_name, gpu_memory, driver, cuda)
        }
        _ => {("Unknown".to_string(), "reserve".to_string(), 0, "reserve".to_string(), "-".to_string())}
    };
    //print!("get_gpu_info.");
    (gpu_brand, gpu_name, gpu_memory/(1024*1024), driver, cuda)
}

fn is_virtual_or_docker_or_physics() -> String {
    match env::consts::OS {
        "linux" => {
            // 检测Docker
            if std::fs::metadata("/.dockerenv").is_ok() {
                return "docker".to_string();
            }
            
            // 检测容器化环境
            if std::fs::metadata("/proc/1/cgroup").is_ok() {
                let cgroup_content = run_command("cat", &["/proc/1/cgroup"]);
                if cgroup_content.contains("docker") || cgroup_content.contains("lxc") {
                    return "container".to_string();
                }
            }
            
            // 检测虚拟机
            let virt_name = run_command("cat", &["/sys/class/dmi/id/product_name"]);
            if !virt_name.is_empty() {
                let virt_name = virt_name.trim();
                // 检查常见虚拟机产品名称
                if virt_name.contains("VMware") || 
                   virt_name.contains("VirtualBox") || 
                   virt_name.contains("KVM") || 
                   virt_name.contains("Xen") {
                    return virt_name.to_string();
                }
                return virt_name.to_string();
            }
            
            "physical".to_string()
        },
        "macos" => {
            // macOS检测虚拟化
            let sysctl_output = run_command("sysctl", &["hw.model"]);
            if sysctl_output.contains("VMware") || sysctl_output.contains("Virtual") {
                return "virtual".to_string();
            }
            "physical".to_string()
        },
        "windows" => {
            // Windows检测虚拟化
            let wmi_output = run_command("powershell", &[
                "-Command", 
                "Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty Model"
            ]);
            
            if wmi_output.contains("VMware") || 
               wmi_output.contains("VirtualBox") || 
               wmi_output.contains("Virtual Machine") {
                return "virtual".to_string();
            }
            "physical".to_string()
        },
        _ => "Unknown".to_string()
    }
}

fn run_command(command: &str, args: &[&str]) -> String {
    match Command::new(command).args(args).output() {
        Ok(output) => {
            if output.status.success() {
                String::from_utf8_lossy(&output.stdout).into_owned()
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                debug!("Failed to run command: {} {:?}, output: {:?}, {}", command, args, output.status.code(), stderr);
                "".to_string()
            }
        }
        Err(e) => {
            debug!("Failed to run command: {} {:?}, error: {:?}", command, args, e);
            "".to_string()
        },
    }
}

fn find_oldest_file(path: &str) -> u64 {
    let dir = Path::new(path);

    if !dir.exists() || !dir.is_dir() {
        eprintln!("路径不存在或不是一个目录: {}", path);
        return 0;
    }

    let mut oldest_time: u64 = u64::MAX;

    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries {
            if let Ok(entry) = entry {
                let path = entry.path();
                if path.is_file() {
                    if let Ok(metadata) = fs::metadata(&path) {
                        if let Ok(modified) = metadata.modified() {
                            if let Ok(duration) = modified.duration_since(UNIX_EPOCH) {
                                let timestamp = duration.as_secs();
                                if timestamp < oldest_time {
                                    oldest_time = timestamp;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    (oldest_time/100000)*100000
}