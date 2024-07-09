from . import utils

paths_checkpoints = ''
paths_loras = ''
path_embeddings = ''
paths_diffusers = ''
paths_controlnet = ''
paths_inpaint = ''

def set_paths(checkpoints, loras, embeddings, diffusers, controlnet, inpaint):
    global paths_checkpoints, paths_loras, path_embeddings, paths_diffusers, paths_controlnet, paths_inpaint

    paths_checkpoints = checkpoints
    paths_loras = loras
    path_embeddings = embeddings
    paths_diffusers = diffusers
    paths_controlnet = controlnet
    paths_inpaint = inpaint

    return



