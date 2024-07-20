import os
import hashlib
from typing import Optional

HASH_SHA256_LENGTH = 10
def sha256(filename, use_addnet_hash=False, length=HASH_SHA256_LENGTH):
    print(f"Calculating sha256 for {filename}: ", end='')
    if use_addnet_hash:
        with open(filename, "rb") as file:
            sha256_value = addnet_hash_safetensors(file)
    else:
        sha256_value = calculate_sha256(filename)
    print(f"{sha256_value}")

    return sha256_value[:length] if length is not None else sha256_value


def addnet_hash_safetensors(b):
    """kohya-ss hash for safetensors from https://github.com/kohya-ss/sd-scripts/blob/main/library/train_util.py"""
    hash_sha256 = hashlib.sha256()
    blksize = 1024 * 1024

    b.seek(0)
    header = b.read(8)
    n = int.from_bytes(header, "little")

    offset = n + 8
    b.seek(offset)
    for chunk in iter(lambda: b.read(blksize), b""):
        hash_sha256.update(chunk)

    return hash_sha256.hexdigest()


def calculate_sha256(filename) -> str:
    hash_sha256 = hashlib.sha256()
    blksize = 1024 * 1024

    with open(filename, "rb") as f:
        for chunk in iter(lambda: f.read(blksize), b""):
            hash_sha256.update(chunk)

    return hash_sha256.hexdigest()

def calculate_sha256_subfolder(folder_path) -> str:
    hash_sha256 = hashlib.sha256()
    blksize = 1024 * 1024
    for entry in os.listdir(folder_path):
        full_path = os.path.join(folder_path, entry)
        if os.path.isfile(full_path):
            with open(full_path, "rb") as f:
                for chunk in iter(lambda: f.read(blksize), b""):
                    hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

def get_size_subfolders(folder_path):
    total_size = 0
    for entry in os.listdir(folder_path):
        full_path = os.path.join(folder_path, entry)
        if os.path.isfile(full_path):
            total_size += os.path.getsize(full_path)
    return total_size

def load_file_from_url(
        url: str,
        *,
        model_dir: str,
        progress: bool = True,
        file_name: Optional[str] = None,
) -> str:
    """Download a file from `url` into `model_dir`, using the file present if possible.

    Returns the path to the downloaded file.
    """
    domain = os.environ.get("HF_MIRROR", "https://huggingface.co").rstrip('/')
    url = str.replace(url, "https://huggingface.co", domain, 1)
    os.makedirs(model_dir, exist_ok=True)
    if not file_name:
        parts = urlparse(url)
        file_name = os.path.basename(parts.path)
    cached_file = os.path.abspath(os.path.join(model_dir, file_name))
    if not os.path.exists(cached_file):
        print(f'Downloading: "{url}" to {cached_file}\n')
        from torch.hub import download_url_to_file
        download_url_to_file(url, cached_file, progress=progress)
    return cached_file

def load_model_for_path(models_url, root_name):
    models_root = folder_paths.get_folder_paths(root_name)[0]
    for model_path in models_url:
        model_full_path = os.path.join(models_root, model_path)
        if not os.path.exists(model_full_path):
            model_full_path = load_file_from_url(
                url=models_url[model_path], model_dir=models_root, file_name=model_path
            )
    return