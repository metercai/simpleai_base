import os
import json
import base64
import hashlib
import requests
import time
from . import models_hub_host
from . import config
from . import utils

models_info = {}
models_info_muid = {}
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

def get_models_info():
    global models_info, models_info_muid
    return models_info, models_info_muid

def init_models_info():
    global models_info, models_info_file, models_info_path

    if os.path.exists(models_info_path):
        file_mtime = time.localtime(os.path.getmtime(models_info_path)) 
        if (models_info is None or file_mtime != models_info_file[1]):
            try:
                with open(models_info_path, "r", encoding="utf-8") as json_file:
                    models_info.update(json.load(json_file))
                models_info_file[1] = file_mtime
            except Exception as e:
                print(f'[ModelInfo] Load model info file [{models_info_path}] failed!')
                print(e)
    refresh_models_info_from_path()
    return
    
def refresh_models_info_from_path():
    global models_info, models_info_file, models_info_path

    model_filenames = config.get_model_filenames(config.paths_checkpoints)
    lora_filenames = config.get_model_filenames(config.paths_loras)
    embedding_filenames = config.get_model_filenames([config.path_embeddings])
    models_info_muid = {}
    new_filenames = []
    new_models_info = {}
    for k in model_filenames:
        filename = 'checkpoints/'+k
        if filename not in models_info.keys():
            new_filenames.append(filename)
        else:
            new_models_info.update({filename: models_info[filename]})
            if models_info[filename]['muid']:
                models_info_muid.update({models_info[filename]['muid']: filename})
    for k in lora_filenames:
        filename = 'loras/'+k
        if filename not in models_info.keys():
            new_filenames.append(filename)
        else:
            new_models_info.update({filename: models_info[filename]})
            if models_info[filename]['muid']:
                models_info_muid.update({models_info[filename]['muid']: filename})
    for k in embedding_filenames:
        filename = 'embeddings/'+k
        if filename not in models_info.keys():
            new_filenames.append(filename)
        else:
            new_models_info.update({filename: models_info[filename]})
            if models_info[filename]['muid']:
                models_info_muid.update({models_info[filename]['muid']: filename})
    models_info = new_models_info

    if len(new_filenames)>0:
        try:
            for f in new_filenames:
                if f.startswith("checkpoints/"):
                    file_path = os.path.join(config.paths_checkpoints[0], f[12:])
                elif f.startswith("loras/"):
                    file_path = os.path.join(config.paths_loras[0], f[6:])
                elif f.startswith("embeddings/"):
                    file_path = os.path.join(config.path_embeddings, f[11:])
                else:
                    file_path = os.path.abspath(f'./models/{f}')
                size = os.path.getsize(file_path)
                if f in default_models_info.keys() and size == default_models_info[f]["size"]:
                    hash = default_models_info[f]["hash"]
                    muid = default_models_info[f]["muid"]
                else:
                    hash = ''
                    muid = ''
                models_info.update({f:{'size': size, 'hash': hash, 'url': None, 'muid': muid}})
            with open(models_info_path, "w", encoding="utf-8") as json_file:
                json.dump(models_info, json_file, indent=4)
            models_info_file[1] = time.localtime(os.path.getmtime(models_info_path))
        except Exception as e:
            print(f'[ModelInfo] Update model info file [{models_info_path}] failed!')
            print(e)
    
    return


def sync_model_info(downurls):
    global models_info, models_info_rsync, models_info_file, models_info_path

    keys = sorted(models_info.keys())
    # file hash completion
    for f in keys:
        if not models_info[f]['hash']:
            print(f'[ModelInfo] Computing file hash for {f}')
            if f.startswith("checkpoints/"):
                file_path = os.path.join(config.paths_checkpoints[0], f[12:])
            elif f.startswith("loras/"):
                file_path = os.path.join(config.paths_loras[0], f[6:])
            elif f.startswith("embeddings/"):
                file_path = os.path.join(config.path_embeddings, f[11:])
            else:
                file_path = os.path.abspath(f'./models/{f}')
            models_info[f].update({'hash':utils.sha256(file_path, length=None)})
    keylist = []
    for i in range(len(keys)):
        if keys[i].startswith('checkpoints'):
            keylist.append(keys[i])
        if keys[i].startswith('loras'):
            keylist.append(keys[i])
    for i in range(len(keys)):
        if not keys[i].startswith('checkpoints') and not keys[i].startswith('loras'):
            keylist.append(keys[i])

    models_info_rsync = {}
    models_info_update_flag = False
    for i in range(len(keylist)):
        #print(f'downurls: i={i}, k={keylist[i]}, {downurls[i]}')
        durl = '' if i >= len(downurls) else downurls[i]
        if durl and models_info[keylist[i]]['url'] != durl:
            models_info_rsync.update({keylist[i]: {"hash": models_info[keylist[i]]['hash'], "url": durl}})
            models_info[keylist[i]]['url'] = durl
            models_info_update_flag = True

    file_mtime = time.localtime(os.path.getmtime(models_info_path))
    for k in models_info.keys():
        if not models_info[k]['muid'] and k not in models_info_rsync.keys():
            models_info_rsync.update({k: {"hash": models_info[k]['hash'], "url": ""}})
    try:
        #response = requests.post(f'{models_hub_host}/register_claim/', data = token_did.get_register_claim('SimpleSDXLHub'))
        #rsync_muid_msg = { "files": token_did.encrypt_default(json.dumps(models_info_rsync)) }
        #headers = { "DID": token_did.DID}
        #response = requests.post(f'{models_hub_host}/rsync_muid/', data = json.dumps(rsync_muid_msg), headers = headers)
        #results = json.loads(response.text)
        #if (results["message"] == "it's ok!" and results["results"]):
        #    for k in results["results"].keys():
        #        models_info[k]['muid'] = results["results"][k]['muid']
        #        models_info_muid[results["results"][k]['muid']] = k
        #        models_info[k]['url'] = results["results"][k]['url']
        #    print(f'[ModelInfo] Rsync {len(results["results"].keys())} MUIDs info from model hub.')
        #    with open(models_info_path, "w", encoding="utf-8") as json_file:
        #        json.dump(models_info, json_file, indent=4)
            models_info_file[1] = time.localtime(os.path.getmtime(models_info_path))
    except Exception as e:
            print(f'[ModelInfo] Connect the models hub site failed!')
            print(e)

    file_mtime2 = time.localtime(os.path.getmtime(models_info_path))
    if (models_info_update_flag and file_mtime == file_mtime2):
        with open(models_info_path, "w", encoding="utf-8") as json_file:
            json.dump(models_info, json_file, indent=4)
        models_info_file[1] = time.localtime(os.path.getmtime(models_info_path))
    return keylist



