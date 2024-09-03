use std::fs;
use std::path::{Path, PathBuf};
use ripemd::{Ripemd160, Digest};
use sha2::{Sha256, Digest as ShaDigest};
use base58::ToBase58;

pub(crate) struct EnvData;

impl EnvData {
    const PYFILE: [( &str, &str); 10] = [
        ("key1", "value1"),
        ("key2", "value2"),
        ("key3", "value3"),
        ("key4", "value4"),
        ("key5", "value5"),
        ("key6", "value6"),
        ("key7", "value7"),
        ("key8", "value8"),
        ("key9", "value9"),
        ("key10", "value10"),
    ];

    const BASEPKG: [(&str, u64); 3] = [
        ("file1.txt", 1024),
        ("subdir/file2.txt", 2048),
        ("another_subdir/file3.txt", 4096),
    ];

    pub fn get_pyhash(v1: &str, v2: &str, v3: &str) -> Option<String> {
        let base58_key = Self::get_pyhash_key(v1, v2, v3);

        for (key, value) in EnvData::PYFILE.iter() {
            if key == &base58_key {
                return Some(value.to_string());
            }
        }
        None
    }

    pub fn get_pyhash_key(v1: &str, v2: &str, v3: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(v1.as_bytes());
        hasher.update(v2.as_bytes());
        let hash1 = hasher.finalize();

        let mut hasher = Sha256::new();
        hasher.update(v3.as_bytes());
        let hash2 = hasher.finalize();

        let combined_hash = [hash1.as_slice(), hash2.as_slice()].concat();

        let ripemd160_hash = Ripemd160::digest(&combined_hash);
        ripemd160_hash.to_vec().to_base58()
    }

    pub fn check_basepkg(root_path: &str) -> bool {
        let basepkg = EnvData::BASEPKG.iter().map(|(filename, size)| {
            (PathBuf::from(filename), *size)
        }).collect::<Vec<_>>();

        for (filename, size) in basepkg {
            let full_path = Path::new(root_path).join(filename);
            if !full_path.exists() {
                return false;
            }
            if let Ok(metadata) = fs::metadata(&full_path) {
                if metadata.len() != size {
                    return false;
                }
            } else {
                return false;
            }
        }
        true
    }
}
