import os
import json
import base64
import hashlib
import requests
import time
from . import models_hub_host
from . import config
from . import utils

models_info_rsync = {}
models_info_file = ['models_info', 0]
models_info_path = os.path.abspath(f'./models/{models_info_file[0]}.json')

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

modelsinfo = None

def get_models_info():
    global modelsinfo
    if modelsinfo is None:
        return {}, {}, {}
    return modelsinfo.m_info, modelsinfo.m_muid, modelsinfo.m_file

def init_models_info():
    global modelsinfo, models_info_path
    models_path_map = {
        'checkpoints': config.paths_checkpoints,
        'loras': config.paths_loras,
        'embeddings': [config.path_embeddings],
    }
    modelsinfo = ModelsInfo(models_info_path, models_path_map)
    return
    
def refresh_models_info_from_path():
    global modelsinfo
    if modelsinfo is None:
        init_models_info()
    modelsinfo.refresh_from_path()
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
                    for k in self.m_info.keys():
                        if self.m_info[k]['muid']:
                            self.m_muid.update({self.m_info[k]['muid']: k})
                        if self.m_info[k]['file']:
                            self.m_file.update({self.m_info[k]['file']: k})
            except Exception as e:
                print(f'[ModelInfo] Load model info file [{self.info_path}] failed!')
                print(e)
                self.m_info = {}
                self.m_muid = {}
                self.m_file = {}
        self.refresh_from_path()

    def refresh_from_path(self):
        new_info_key = []
        new_file_key = []
        del_file_key = []
        for path in self.path_map.keys():
            if self.path_map[path]:
                path_filenames = config.get_model_filenames(self.path_map[path])
                for k in path_filenames:
                    file_key = f'{path}/{k}'
                    new_info_key.append(file_key)
                    if file_key not in self.m_info.keys():
                        new_file_key.append(file_key)
        for k in self.m_info.keys():
            if k not in new_info_key:
                del_file_key.append(k)
        for f in new_file_key:
            f_path = f.split('/')[0]
            file_path = ''
            for path in self.path_map[f_path]:
                    file_path = os.path.join(path, f[len(f_path)+1:])
                    if os.path.exists(file_path):
                        break
            size = os.path.getsize(file_path)
            if f in default_models_info.keys() and size == default_models_info[f]["size"]:
                hash = default_models_info[f]["hash"]
                muid = default_models_info[f]["muid"]
            else:
                hash = '' # utils.sha256(file_path, length=None)
                muid = '' # utils.sha256(file_path, use_addnet_hash=True)
            self.m_info.update({f:{'size': size, 'hash': hash, 'file': file_path, 'muid': muid, 'url': None}})
            self.m_muid.update({muid: f})
            self.m_file.update({file_path: f})
        for f in del_file_key:
            if self.m_info[f]['muid'] and self.m_info[f]['muid'] in self.m_muid.keys():
                del self.m_muid[self.m_info[f]['muid']]
            if self.m_info[f]['file'] and self.m_info[f]['file'] in self.m_file.keys():
                del self.m_file[self.m_info[f]['file']]
            del self.m_info[f]
        with open(self.info_path, "w", encoding="utf-8") as json_file:
            json.dump(self.m_info, json_file, indent=4)




