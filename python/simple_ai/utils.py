import os
import hashlib

folder_variation = {}
def get_files_from_folder(folder_path, extensions=None, name_filter=None, variation=False):
    global folder_variation

    if not os.path.isdir(folder_path):
        raise ValueError("Folder path is not a valid directory.")

    filenames = []
    for root, dirs, files in os.walk(folder_path, topdown=False):
        relative_path = os.path.relpath(root, folder_path)
        if relative_path == ".":
            relative_path = ""
        for filename in sorted(files, key=lambda s: s.casefold()):
            _, file_extension = os.path.splitext(filename)
            if (extensions is None or file_extension.lower() in extensions) and (name_filter is None or name_filter in _):
                path = os.path.join(relative_path, filename)
                if variation:
                    mtime = int(os.path.getmtime(os.path.join(root, filename)))
                    if folder_path not in folder_variation or path not in folder_variation[folder_path] or mtime > folder_variation[folder_path][path]:
                        if folder_path not in folder_variation:
                            folder_variation.update({folder_path: {path: mtime}})
                        else:
                            folder_variation[folder_path].update({path: mtime})
                        filenames.append(path)
                else:
                    filenames.append(path)


    return filenames

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
