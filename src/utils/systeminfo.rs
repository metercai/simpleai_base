use serde::{Deserialize, Serialize};
use pyo3::prelude::*;
use std::process::Command;
use std::env;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};


use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
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
        if gpu_brand=="Unknown" || gpu_name=="reserve" || gpu_memory==0 {
            let ram_gpu_info = env_utils::get_ram_and_gpu_info();
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

        let host_type = is_virtual_or_docker_or_physics();

        let mut sys = System::new_all();
        sys.refresh_all();
        let os_type = env::consts::OS.to_string();
        let os_name = format!("{} {}", System::name().unwrap_or("Unknown".to_string()), System::os_version().unwrap_or("Unknown".to_string()));
        let host_name = System::host_name().unwrap_or("Unknown".to_string());
        let cpu_arch = env::consts::ARCH.to_string();
        let (cpu_brand, cpu_cores) = (sys.cpus()[0].brand(), sys.physical_core_count());
        let (ram_total, ram_free, ram_swap) = (sys.total_memory(), sys.available_memory(), sys.total_swap());

        let root_dir = env::current_dir().unwrap_or_else(|e| {
            tracing::error!("env::current_dir, error:{:?}", e);
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
        debug!("os_time: {}, root_time: {}", os_time, root_time);

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
            let total = run_command("powershell", &["(Get-CimInstance Win32_LogicalDisk -Filter \"DeviceID='C:'\").Size"]).trim().parse::<u64>().unwrap_or(0);
            let free = run_command("powershell", &["(Get-CimInstance Win32_LogicalDisk -Filter \"DeviceID='C:'\").FreeSpace"]).trim().parse::<u64>().unwrap_or(0);
            let uuid = run_command("powershell", &["(Get-CimInstance Win32_LogicalDisk -Filter \"DeviceID='C:'\").VolumeSerialNumber"]).trim().to_string();
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
            (total/2, free/2, uuid)
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
            ("Apple".to_string(), "reserve".to_string(), 0, "reserve".to_string(), "-".to_string())
        }
        _ => {("Unknown".to_string(), "reserve".to_string(), 0, "reserve".to_string(), "-".to_string())}
    };
    //print!("get_gpu_info.");
    (gpu_brand, gpu_name, gpu_memory, driver, cuda)
}

fn is_virtual_or_docker_or_physics() -> String {
    let device_type = match env::consts::OS {
        "linux" => {
            let path = "/.dockerenv";
            match std::fs::metadata(path) {
                Ok(_) => {
                    "docker".to_string()
                }
                Err(_) => {
                    let virt_name = run_command("cat", &["/sys/class/dmi/id/product_name"]);
                    virt_name.trim().to_string()
                }
            }
        }
        _ => {
            "Unknown".to_string()
        }
    };
    device_type
}

fn run_command(command: &str, args: &[&str]) -> String {
    match Command::new(command).args(args).output() {
        Ok(output) => {
            if output.status.success() {
                String::from_utf8_lossy(&output.stdout).into_owned()
            } else {
                debug!("Failed to run command: {} {:?}, output: {:?}", command, args, output);
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

    let mut oldest_time: u64 = 0;

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