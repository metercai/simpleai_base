use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use serde_json;
use sha2::{Sha256, Digest};

struct ModelsInfo {
    info_path: String,
    path_map: HashMap<String, Vec<String>>,
    m_info: HashMap<String, ModelInfo>,
    m_muid: HashMap<String, Vec<String>>,
    m_file: HashMap<String, String>,
    scan_models_hash: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ModelInfo {
    size: u64,
    hash: String,
    file: Vec<String>,
    muid: String,
    url: String,
}

impl ModelsInfo {
    fn new(models_info_path: String, path_map_json: String, scan_hash: bool) -> Result<Self, Box<dyn std::error::Error>> {
        let path_map: HashMap<String, Vec<String>> = serde_json::from_str(&path_map_json)?;
        let mut models_info = ModelsInfo {
            info_path: models_info_path,
            path_map,
            m_info: HashMap::new(),
            m_muid: HashMap::new(),
            m_file: HashMap::new(),
            scan_models_hash: scan_hash,
        };
        models_info.load_model_info()?;
        models_info.refresh_from_path();
        Ok(models_info)
    }

    fn get_stat(&self) -> usize {
        self.m_info.len()
    }

    fn load_model_info(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if Path::new(&self.info_path).exists() {
            let json_str = fs::read_to_string(&self.info_path)?;
            let mut loaded_info: HashMap<String, ModelInfo> = serde_json::from_str(&json_str)?;
            let mut file_no_exists_list = Vec::new();
            for (k, v) in loaded_info.iter() {
                if let Some(file_list) = &v.file {
                    let mut valid_files = Vec::new();
                    for file in file_list {
                        if Path::new(file).exists() {
                            self.m_file.insert(file.clone(), k.clone());
                            valid_files.push(file.clone());
                        }
                    }
                    if valid_files.is_empty() {
                        file_no_exists_list.push(k.clone());
                    } else {
                        loaded_info.get_mut(k).unwrap().file = valid_files;
                    }
                }
                if !file_no_exists_list.contains(k) && !v.muid.is_empty() {
                    self.update_muid_map(&v.muid, k);
                }
            }
            for k in file_no_exists_list {
                loaded_info.remove(&k);
            }
            self.m_info = loaded_info;
        }
        Ok(())
    }

    fn update_muid_map(&mut self, muid: &str, model_key: &str) {
        if let Some(existing_keys) = self.m_muid.get_mut(muid) {
            existing_keys.push(model_key.to_string());
        } else {
            self.m_muid.insert(muid.to_string(), vec![model_key.to_string()]);
        }
    }

    fn refresh_from_path(&mut self) {
        let mut new_info_key = HashSet::new();
        let mut new_model_key = Vec::new();
        let mut del_model_key = Vec::new();
        let mut new_model_file = HashMap::new();
        let mut new_file_key = HashSet::new();
        let mut del_file_key = Vec::new();

        for (path, paths) in self.path_map.iter() {
            if let Some(path_filenames) = self.get_path_filenames(path) {
                for (p, k) in path_filenames {
                    let model_key = format!("{}/{}", path, k.replace(std::path::MAIN_SEPARATOR, "/"));
                    let file_path = format!("{}/{}", p, k);
                    new_file_key.insert(file_path.clone());
                    new_model_file.entry(model_key.clone())
                        .or_insert_with(Vec::new)
                        .push(file_path.clone());
                    new_info_key.insert(model_key.clone());
                    if !self.m_info.contains_key(&model_key) {
                        new_model_key.push(model_key.clone());
                    }
                }
            }
        }

        for k in self.m_info.keys() {
            if !new_info_key.contains(k) {
                del_model_key.push(k.clone());
            }
        }

        for f in self.m_file.keys() {
            if !new_file_key.contains(f) {
                del_file_key.push(f.clone());
            }
        }

        for f in new_model_key {
            self.add_new_model(&f, &new_model_file);
        }

        for f in del_model_key {
            self.remove_model(&f);
        }

        for f in del_file_key {
            self.remove_file(&f);
        }

        self.save_model_info();
    }

    fn get_path_filenames(&self, path: &str) -> Option<Vec<(String, String)>> {
        if path.chars().all(|c| c.is_uppercase()) {
            let mut path_filenames = Vec::new();
            if let Some(paths) = self.path_map.get(path) {
                for f_path in paths {
                    if let Ok(entries) = fs::read_dir(f_path) {
                        for entry in entries.flatten() {
                            if entry.path().is_dir() {
                                path_filenames.push((f_path.clone(), entry.file_name().to_string_lossy().to_string()));
                            }
                        }
                    }
                }
            }
            Some(path_filenames)
        } else {
            self.get_model_filenames(self.path_map.get(path).unwrap())
        }
    }

    fn add_new_model(&mut self, model_key: &str, new_model_file: &HashMap<String, Vec<String>>) {
        if let Some(file_paths) = new_model_file.get(model_key) {
            let file_path = file_paths[0].clone();
            let (size, hash, muid) = self.calculate_model_info(&file_path);
            self.m_info.insert(model_key.to_string(), ModelInfo {
                size,
                hash,
                file: file_paths.clone(),
                muid: muid.clone(),
                url: String::new(),
            });
            self.update_muid_map(&muid, model_key);
            for file_path in file_paths {
                self.m_file.insert(file_path.clone(), model_key.to_string());
            }
        }
    }

    fn remove_model(&mut self, model_key: &str) {
        if let Some(model_info) = self.m_info.get(model_key) {
            if let Some(muid) = &model_info.muid {
                self.remove_muid_map(muid, model_key);
            }
            if let Some(file_paths) = &model_info.file {
                self.remove_file_map(file_paths, model_key);
            }
        }
        self.m_info.remove(model_key);
    }

    fn remove_file(&mut self, file_path: &str) {
        if let Some(model_key) = self.m_file.get(file_path) {
            if let Some(model_info) = self.m_info.get_mut(model_key) {
                if let Some(file_paths) = &mut model_info.file {
                    if let Some(pos) = file_paths.iter().position(|x| x == file_path) {
                        file_paths.remove(pos);
                        if file_paths.len() == 1 {
                            model_info.file = vec![file_paths[0].clone()];
                        }
                    }
                }
            }
        }
        self.m_file.remove(file_path);
    }

    fn remove_muid_map(&mut self, muid: &str, model_key: &str) {
        if let Some(keys) = self.m_muid.get_mut(muid) {
            if let Some(pos) = keys.iter().position(|x| x == model_key) {
                keys.remove(pos);
                if keys.len() == 1 {
                    self.m_muid.insert(muid.to_string(), vec![keys[0].clone()]);
                }
            }
        }
    }

    fn remove_file_map(&mut self, file_paths: &[String], model_key: &str) {
        for file_path in file_paths {
            self.m_file.remove(file_path);
        }
    }

    fn calculate_model_info(&self, file_path: &str) -> (u64, String, String) {
        let size = if Path::new(file_path).is_dir() {
            get_size_subfolders(file_path)
        } else {
            fs::metadata(file_path).map(|m| m.len()).unwrap_or(0)
        };

        let hash = if let Some(default_info) = default_models_info().get(file_path) {
            if default_info.size == size {
                default_info.hash.clone()
            } else {
                self.calculate_hash(file_path)
            }
        } else {
            self.calculate_hash(file_path)
        };

        let muid = if Path::new(file_path).extension().map(|ext| ext == "safetensors").unwrap_or(false) {
            self.calculate_addnet_hash(file_path)
        } else {
            hash.chars().take(10).collect()
        };

        (size, hash, muid)
    }

    fn calculate_hash(&self, file_path: &str) -> String {
        let mut hasher = Sha256::new();
        if Path::new(file_path).is_dir() {
            for entry in fs::read_dir(file_path).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                if path.is_file() {
                    let data = fs::read(path).unwrap();
                    hasher.update(data);
                }
            }
        } else {
            let data = fs::read(file_path).unwrap();
            hasher.update(data);
        }
        format!("{:x}", hasher.finalize())
    }

    fn calculate_addnet_hash(&self, file_path: &str) -> String {
        let mut hasher = Sha256::new();
        let data = fs::read(file_path).unwrap();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }

    fn save_model_info(&self) {
        let json_str = serde_json::to_string_pretty(&self.m_info).unwrap();
        if let Err(e) = fs::write(&self.info_path, json_str) {
            eprintln!("[SimpleAI] Models info update and save failed: {}", e);
        }
    }

    fn refresh_file(&mut self, action: &str, file_path: &str) {
        match action {
            "add" => {
                if !Path::new(file_path).exists() {
                    eprintln!("[ModelInfo] The added file does not exist: {:?}", file_path);
                    return;
                }

                let catalog = self.path_map.iter()
                    .filter(|(_, paths)| paths.iter().any(|p| file_path.starts_with(p)))
                    .max_by_key(|(_, paths)| paths.iter().map(|p| p.len()).max().unwrap_or(0))
                    .map(|(k, _)| k.clone());

                if let Some(catalog) = catalog {
                    let model_name = file_path.strip_prefix(&catalog).unwrap().to_string_lossy().to_string();
                    let model_key = format!("{}/{}", catalog, model_name);
                    let (size, hash, muid) = self.calculate_model_info(file_path);
                    self.m_info.insert(model_key.clone(), ModelInfo {
                        size,
                        hash,
                        file: vec![file_path.to_string()],
                        muid: muid.clone(),
                        url: String::new(),
                    });
                    self.update_muid_map(&muid, &model_key);
                    self.m_file.insert(file_path.to_string(), model_key.clone());
                    println!("[ModelInfo] Added model {} with file {:?}", model_key, file_path);
                } else {
                    eprintln!("[ModelInfo] The added file path {:?} does not match any path in path_map.", file_path);
                }
            }
            "delete" => {
                if let Some(model_key) = self.m_file.get(file_path) {
                    let muid = self.m_info.get(model_key).unwrap().muid.clone();
                    self.m_info.remove(model_key);
                    self.remove_muid_map(&muid, model_key);
                    self.m_file.remove(file_path);
                    println!("[ModelInfo] Deleted model {} with file {:?}", model_key, file_path);
                } else {
                    eprintln!("[ModelInfo] File not found in model info: {:?}", file_path);
                }
            }
            _ => {
                eprintln!("[ModelInfo] Invalid action: {}. Action must be either \"add\" or \"delete\".", action);
            }
        }

        self.save_model_info();
    }

    fn exists_model(&self, catalog: &str, model_path: &str, muid: Option<&str>) -> bool {
        if let Some(muid) = muid {
            if self.m_muid.contains_key(muid) {
                return true;
            }
        }

        for (k, v) in self.m_info.iter() {
            let cata = k.split('/').next().unwrap();
            let m_path_or_file = &k[cata.len() + 1..];
            if model_path.is_empty() || (catalog == cata && m_path_or_file == model_path) {
                return true;
            }
        }

        false
    }

    fn exists_model_key(&self, model_key: &str) -> bool {
        self.m_info.contains_key(model_key)
    }

    fn get_model_filepath(&self, catalog: &str, model_path: &str, muid: Option<&str>) -> Option<String> {
        if let Some(muid) = muid {
            if let Some(keys) = self.m_muid.get(muid) {
                if let Some(model_info) = self.m_info.get(&keys[0]) {
                    return Some(model_info.file[0].clone());
                }
            }
        }

        if !catalog.is_empty() && !model_path.is_empty() {
            for (k, v) in self.m_info.iter() {
                let cata = k.split('/').next().unwrap();
                let m_path_or_file = &k[cata.len() + 1..];
                if cata == catalog && m_path_or_file == model_path {
                    return Some(v.file[0].clone());
                }
            }
        }

        None
    }

    fn get_model_names(&self, catalog: &str, filters: &[&str], casesensitive: bool, reverse: bool) -> Vec<String> {
        let mut result = Vec::new();
        let mut result_reverse = Vec::new();

        for (k, _) in self.m_info.iter() {
            let cata = k.split('/').next().unwrap();
            let m_path_or_file = &k[cata.len() + 1..].replace('/', &std::path::MAIN_SEPARATOR.to_string());
            if catalog == cata {
                result_reverse.push(m_path_or_file.to_string());
                if !filters.is_empty() {
                    for item in filters {
                        if casesensitive {
                            if m_path_or_file.contains(item) {
                                result.push(m_path_or_file.to_string());
                                result_reverse.pop();
                                break;
                            }
                        } else {
                            if m_path_or_file.to_lowercase().contains(&item.to_lowercase()) {
                                result.push(m_path_or_file.to_string());
                                result_reverse.pop();
                                break;
                            }
                        }
                    }
                } else {
                    result.push(m_path_or_file.to_string());
                    result_reverse.pop();
                }
            }
        }

        if reverse {
            result_reverse
        } else {
            result
        }
    }

    fn get_model_info(&self, catalog: &str, model_name: &str) -> Option<&ModelInfo> {
        let model_key = format!("{}/{}", catalog, model_name);
        self.m_info.get(&model_key)
    }

    fn get_model_key_info(&self, model_key: &str) -> Option<&ModelInfo> {
        self.m_info.get(model_key)
    }

    fn get_file_muid(&self, file_path: &str) -> Option<String> {
        if let Some(model_key) = self.m_file.get(file_path) {
            if let Some(model_info) = self.m_info.get(model_key) {
                return Some(model_info.muid.clone());
            }
        }
        None
    }
}

fn get_model_filenames(folder_paths: &[String], extensions: Option<&[&str]>, name_filter: Option<&str>) -> Vec<(String, String)> {
    let extensions = extensions.unwrap_or(&[".pth", ".ckpt", ".bin", ".safetensors", ".fooocus.patch", ".gguf"]);
    let mut files = Vec::new();
    for folder in folder_paths {
        files.extend(get_files_from_folder(folder, extensions, name_filter));
    }
    files
}

fn get_files_from_folder(folder_path: &str, extensions: &[&str], name_filter: Option<&str>) -> Vec<(String, String)> {
    let mut filenames = Vec::new();
    if let Ok(entries) = fs::read_dir(folder_path) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Some(file_name) = path.file_name() {
                    let file_name = file_name.to_string_lossy().to_string();
                    if let Some(ext) = path.extension() {
                        if extensions.contains(&ext.to_str().unwrap()) && (name_filter.is_none() || file_name.contains(name_filter.unwrap())) {
                            filenames.push((folder_path.to_string(), file_name));
                        }
                    }
                }
            }
        }
    }
    filenames
}

fn get_size_subfolders(folder_path: &str) -> u64 {
    let mut total_size = 0;
    if let Ok(entries) = fs::read_dir(folder_path) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Ok(metadata) = fs::metadata(&path) {
                    total_size += metadata.len();
                }
            } else if path.is_dir() {
                total_size += get_size_subfolders(&path.to_string_lossy().to_string());
            }
        }
    }
    total_size
}

fn default_models_info() -> HashMap<String, ModelInfo> {
    // Placeholder for default models info
    HashMap::new()
}