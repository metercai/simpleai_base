import os
import json
from pathlib import Path
from . import models_hub_host
from . import config
from . import utils
from simpleai_base import simpleai_base

models_info_rsync = {}
models_info_file = ['models_info', 0]
models_info_path = os.path.abspath(os.path.join(config.path_models_root, f'{models_info_file[0]}.json'))

default_models_info = {
    "checkpoints/albedobaseXL_v21.safetensors": {
        "size": 6938041042,
        "hash": "1718b5bb2da1ef4815fee8af8a7fc2fa8ab8f467b279eded4d991ea0cce59a6d",
        "muid": "acf28f1aeb42"
    },
    "checkpoints/animaPencilXL_v310.safetensors": {
        "size": 6938040682,
        "hash": "67b97ee6eec64abf0cb73c2284a0afecdd8e205a87a3622c2c23231e25e29b5b",
        "muid": "2def60f4b273"
    },
    "checkpoints/juggernaut-X-RunDiffusion-NSFW.safetensors": {
        "size": 7105348672,
        "hash": "d91d35736d8f2be038f760a9b0009a771ecf0a417e9b38c244a84ea4cb9c0c45",
        "muid": "039986f26f01"
    },
    "checkpoints/juggernautXL_v8Rundiffusion.safetensors": {
        "size": 7105348592,
        "hash": "aeb7e9e6897a1e58b10494bd989d001e3d4bc9b634633cd7b559838f612c2867",
        "muid": "f84d1c1e05d4"
    },
    "checkpoints/juggernautXL_v9Rundiffusionphoto2.safetensors": {
        "size": 7105348188,
        "hash": "c9e3e68f89b8e38689e1097d4be4573cf308de4e3fd044c64ca697bdb4aa8bca",
        "muid": "393f61fcece8"
    },
    "checkpoints/playground-v2.5-1024px.safetensors": {
        "size": 6938040576,
        "hash": "bcaa7dd6780974f000b17b5a6c63e6f867a75c51ffa85c67d6b196882c69b992",
        "muid": "d0e21c789d50"
    },
    "checkpoints/realisticStockPhoto_v20.safetensors": {
        "size": 6938054242,
        "hash": "f99f3dec38a09b4834a4a073bdc45aabd42b422b4d327f5e8001afcb5ffb5f45",
        "muid": "5d99d6fc4fbf"
    },
    "checkpoints/realisticVisionV60B1_v51VAE.safetensors": {
        "size": 2132625894,
        "hash": "15012c538f503ce2ebfc2c8547b268c75ccdaff7a281db55399940ff1d70e21d",
        "muid": "5da06f78b3c8"
    },
    "checkpoints/sd3_medium_incl_clips.safetensors": {
        "size": 5973224240,
        "hash": "3bb7f21bc5fb450220f4eb78a2f276b15422309d5166a4bdeb8c3b763a3a0581",
        "muid": "bb3cbb3221ef"
    },
    "checkpoints/sd3_medium_incl_clips_t5xxlfp16.safetensors": {
        "size": 15761074532,
        "hash": "69a950c5d143ce782a7423c532c8a12b75da6a37b0e6f26a322acf4e76208912",
        "muid": "c3a45b17d217"
    },
    "checkpoints/sd3_medium_incl_clips_t5xxlfp8.safetensors": {
        "size": 10867168284,
        "hash": "92db4295e9c9ab8401ef60566d975656a35b0bd0f6d9ce0d083725171f7b3174",
        "muid": "41d49489bc24"
    },
    "checkpoints/sd_xl_base_1.0_0.9vae.safetensors": {
        "size": 6938078334,
        "hash": "e6bb9ea85bbf7bf6478a7c6d18b71246f22e95d41bcdd80ed40aa212c33cfeff",
        "muid": "5e756477ea9d"
    },
    "checkpoints/sd_xl_refiner_1.0_0.9vae.safetensors": {
        "size": 6075981930,
        "hash": "8d0ce6c016004cbdacd50f937dad381d8c396628d621a7f97191470532780164",
        "muid": "bd66e233fe56"
    },
    "loras/FilmVelvia3.safetensors": {
        "size": 151108832,
        "hash": "ac8b0e4aa77be4d8b83da9bafe0134a2e36504c9b5263a7030394cffe4f7003a",
        "muid": "6e93473d6228"
    },
    "loras/ip-adapter-faceid-plusv2_sdxl_lora.safetensors": {
        "size": 371842896,
        "hash": "f24b4bb2dad6638a09c00f151cde84991baf374409385bcbab53c1871a30cb7b",
        "muid": "13623d29c464"
    },
    "loras/sd_xl_offset_example-lora_1.0.safetensors": {
        "size": 49553604,
        "hash": "4852686128f953d0277d0793e2f0335352f96a919c9c16a09787d77f55cbdf6f",
        "muid": "8e3e833226b3"
    },
    "loras/SDXL_FILM_PHOTOGRAPHY_STYLE_BetaV0.4.safetensors": {
        "size": 232957560,
        "hash": "bc6db9d8f167adf51c2ad9280cccaff108fc8a6d6e8cd654e3afcfdbf13e1048",
        "muid": "e1474929e3e2"
    },
    "loras/sdxl_hyper_sd_4step_lora.safetensors": {
        "size": 787359648,
        "hash": "12f81a27d00a751a40d68fd15597091896c5a90f3bd632fb6c475607cbdad76e",
        "muid": "1c88f7295856"
    },
    "loras/sdxl_lcm_lora.safetensors": {
        "size": 393854624,
        "hash": "c3dbf7eb26dd00ae6b6b95da69be9f1cb95a3b2c5bcf9be82323227a19b91329",
        "muid": "3d18b05e4f56"
    },
    "loras/sdxl_lightning_4step_lora.safetensors": {
        "size": 393854592,
        "hash": "bf56cf2657efb15e465d81402ed481d1e11c4677e4bcce1bc11fe71ad8506b79",
        "muid": "1c32bdb07a7c"
    },
    "embeddings/unaestheticXLhk1.safetensors": {
        "size": 33296,
        "hash": "ca29d24a64c1801efc82f8f4d05d98308e5b6c51c15d156fb61ac074f24f87ce",
        "muid": "63578af5d493"
    },
    "embeddings/unaestheticXLv31.safetensors": {
        "size": 33296,
        "hash": "75fa9a0423a19c56ccaaea3b985b4999408b530585eca3f6108685c0007e5b2e",
        "muid": "a20bca3b2146"
    }
}

history_models_info = {}
modelsinfo = None

def get_models_info():
    global modelsinfo
    if modelsinfo is None:
        return {}, {}, {}
    return modelsinfo.m_info, modelsinfo.m_muid, modelsinfo.m_file

def get_modelsinfo():
    global modelsinfo
    if modelsinfo is None:
        init_models_info()
    modelsinfo.refresh_from_path()
    return modelsinfo

def refresh_models_info_from_path():
    global modelsinfo
    if modelsinfo is None:
        init_models_info()
    modelsinfo.refresh_from_path()
    return

def init_models_info():
    global modelsinfo, models_info_path
    models_info_path = os.path.abspath(os.path.join(config.path_models_root, 'models_info.json'))
    print(f'[SimpleAI] The path of models_info.json: {models_info_path}')

    models_path_map = {
        'checkpoints': config.paths_checkpoints,
        'loras': config.paths_loras,
        'embeddings': [config.path_embeddings],
        'diffusers' : config.paths_diffusers,
        'DIFFUSERS': config.paths_diffusers,
        'controlnet' : config.paths_controlnet,
        'inpaint' : config.paths_inpaint,
        'unet' : [config.path_unet],
        'llms' : config.paths_llms,
        'vae' : [config.path_vae]
    }
    modelsinfo = ModelsInfo(models_info_path, models_path_map)
    return
    


def sync_model_info(downurls):
    global models_info, models_info_rsync, models_info_file, models_info_path
    print(f'downurls:{downurls}')
    keylist = []
    return keylist


class ModelsInfo:
    def __init__(self, models_info_path, path_map):
        self.info_path = models_info_path
        self.path_map = path_map
        self.m_info = {}
        self.m_muid = {}
        self.m_file = {}
        if os.path.exists(self.info_path):
            try:
                with open(self.info_path, "r", encoding="utf-8") as json_file:
                    self.m_info.update(json.load(json_file))
                    file_no_exists_list = []
                    for k in self.m_info.keys():
                        if self.m_info[k]['file']:
                            if isinstance(self.m_info[k]['file'], list):
                                file_list = []
                                for file in self.m_info[k]['file']:
                                    if os.path.exists(file):
                                        self.m_file.update({file: k})
                                        file_list.append(file)
                                if len(file_list) > 1:
                                    self.m_info[k]['file'] = file_list
                                elif len(file_list) == 1:
                                    self.m_info[k]['file'] = file_list[0]
                                else:
                                    file_no_exists_list.append(k)
                            else:
                                if os.path.exists(self.m_info[k]['file']):
                                    self.m_file.update({self.m_info[k]['file']: k})
                                else:
                                    file_no_exists_list.append(k)
                        if k not in file_no_exists_list and self.m_info[k]['muid']:
                            if self.m_info[k]['muid'] in self.m_muid and self.m_muid[self.m_info[k]['muid']]:
                                muid_files = self.m_muid[self.m_info[k]['muid']]
                                if isinstance(muid_files, list):
                                    muid_files.append(k)
                                else:
                                    muid_files = [muid_files, k]
                                self.m_muid.update({self.m_info[k]['muid']: muid_files})
                            else:
                                self.m_muid.update({self.m_info[k]['muid']: k})
                    for k in file_no_exists_list:
                        del self.m_info[k]
            except Exception as e:
                print(f'[ModelInfo] Load model info file [{self.info_path}] failed!, error:{e}')
                self.m_info = {}
                self.m_muid = {}
                self.m_file = {}
        self.refresh_from_path()

    def refresh_from_path(self):
        new_info_key = []
        new_model_key = []
        del_model_key = []
        new_model_file = {}
        new_file_key = []
        del_file_key = []
        for path in self.path_map.keys():
            if self.path_map[path]:
                if path.isupper():
                    path_filenames = []
                    for f_path in self.path_map[path]:
                        path_filenames += [(f_path, entry) for entry in os.listdir(f_path) if os.path.isdir(os.path.join(f_path, entry))]
                else:
                    path_filenames = get_model_filenames(self.path_map[path])
                #print(f'path_filenames_{path}:{path_filenames}')
                for (p,k) in path_filenames:
                    model_key = f'{path}/{k}'
                    file_path = os.path.join(p, k)
                    if file_path not in new_file_key:
                        new_file_key.append(file_path)
                    if model_key in new_model_file:
                        if isinstance(new_model_file[model_key], list):
                            new_model_file[model_key].append(file_path)
                        else:
                            new_model_file[model_key] = [new_model_file[model_key], file_path]
                    else:
                        new_model_file[model_key] = file_path
                    if model_key not in new_info_key:
                        new_info_key.append(model_key)
                    if model_key not in self.m_info.keys():
                        new_model_key.append(model_key)

        for k in self.m_info.keys():
            if k not in new_info_key:
                del_model_key.append(k)
        for f in self.m_file.keys():
            if f not in new_file_key:
                del_file_key.append(f)
        for f in new_model_key:
            f_path = f.split('/')[0]
            file_path = new_model_file[f]
            if isinstance(file_path, list):
                file_path = file_path[0]
            if f_path.isupper():
                size = utils.get_size_subfolders(file_path)
            else:
                size = os.path.getsize(file_path)
            if f in default_models_info.keys() and size == default_models_info[f]["size"]:
                hash = default_models_info[f]["hash"]
                muid = default_models_info[f]["muid"]
            else:
                hash = '' # utils.sha256(file_path, length=None)
                muid = '' # utils.sha256(file_path, use_addnet_hash=True)
            self.m_info.update({f:{'size': size, 'hash': hash, 'file': new_model_file[f], 'muid': muid, 'url': None}})
            if muid in self.m_muid:
                if isinstance(self.m_muid[muid], list):
                    self.m_muid[muid].append(f)
                else:
                    self.m_muid[muid] = [self.m_muid[muid], f]
            else:
                self.m_muid.update({muid: f})
            if isinstance(new_model_file[f], list):
                for file_path in new_model_file[f]:
                    self.m_file.update({file_path: f})
            else:
                self.m_file.update({new_model_file[f]: f})
        for f in del_model_key:
            if self.m_info[f]['muid'] and self.m_info[f]['muid'] in self.m_muid.keys():
                if isinstance(self.m_muid[self.m_info[f]['muid']], list):
                    if f in self.m_muid[self.m_info[f]['muid']]:
                        self.m_muid[self.m_info[f]['muid']].remove(f)
                    if len(self.m_muid[self.m_info[f]['muid']]) == 1:
                        self.m_muid[self.m_info[f]['muid']] = self.m_muid[self.m_info[f]['muid']][0]
                else:
                    del self.m_muid[self.m_info[f]['muid']]

            if self.m_info[f]['file']:
                if isinstance(self.m_info[f]['file'], list):
                    for file_path in self.m_info[f]['file']:
                        if file_path in self.m_file.keys():
                            del self.m_file[file_path]
                else:
                    del self.m_file[self.m_info[f]['file']]
            del self.m_info[f]
        for f in del_file_key:
            if f in self.m_file.keys() and self.m_file[f] in self.m_info.keys() \
                    and self.m_info[self.m_file[f]]['file']:
                file_paths = self.m_info[self.m_file[f]]['file']
                if isinstance(file_paths, list):
                    if f in file_paths:
                        file_paths.remove(f)
                    if len(file_paths) == 1:
                        self.m_info[self.m_file[f]]['file'] = file_paths[0]
            else:
                if f in self.m_file.keys():
                    del self.m_file[f]
        with open(self.info_path, "w", encoding="utf-8") as json_file:
            json.dump(self.m_info, json_file, indent=4)

    def exists_model(self, catalog='', model_path='', muid=None):
        if muid and self.m_muid[muid]:
            return True
        for f in self.m_info.keys():
            cata = f.split('/')[0]
            m_path_or_file = f[len(cata)+1:].replace('\\', '/')
            if model_path:
                model_path = model_path.replace('\\', '/')
                if catalog and cata == catalog and m_path_or_file == model_path:
                    return True
        return False

    def get_model_filepath(self, catalog='', model_path='', muid=None):
        if muid and not model_path and self.m_muid[muid]:
            if isinstance(self.m_muid[muid], list):
                file_paths = self.m_info[self.m_muid[muid][0]]
            else:
                file_paths = self.m_info[self.m_muid[muid]]
            if isinstance(file_paths, list):
                return file_paths[0]
            else:
                return file_paths
        if catalog and model_path:
            for f in self.m_info.keys():
                cata = f.split('/')[0]
                m_path_or_file = f[len(cata)+1:].replace('\\', '/')
                model_path = model_path.replace('\\', '/')
                if cata == catalog and m_path_or_file == model_path:
                    file_paths = self.m_info[f]['file']
                    if isinstance(file_paths, list):
                        return file_paths[0]
                    else:
                        return file_paths
        return ''


    def get_model_info(self, catalog, model_name):
        return self.m_info[f'{catalog}/{model_name}']


def get_model_filenames(folder_paths, extensions=None, name_filter=None):
    if extensions is None:
        extensions = ['.pth', '.ckpt', '.bin', '.safetensors', '.fooocus.patch']
    files = []
    for folder in folder_paths:
        files += get_files_from_folder(folder, extensions, name_filter)
    return files


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
                        filenames.append((folder_path,path))
                else:
                    filenames.append((folder_path, path))
    return filenames
