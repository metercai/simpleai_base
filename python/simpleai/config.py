from . import utils

paths_checkpoints = ''
paths_loras = ''
path_embeddings = ''

def set_paths(checkpoints, loras, embeddings):
    global paths_checkpoints, paths_loras, path_embeddings

    paths_checkpoints = checkpoints
    paths_loras = loras
    path_embeddings = embeddings


def get_model_filenames(folder_paths, extensions=None, name_filter=None):
    if extensions is None:
        extensions = ['.pth', '.ckpt', '.bin', '.safetensors', '.fooocus.patch']
    files = []
    for folder in folder_paths:
        files += utils.get_files_from_folder(folder, extensions, name_filter)
    return files
