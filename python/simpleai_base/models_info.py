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
        "checkpoints/animaPencilXL_v500.safetensors": {
            "size": 6938041144,
            "hash": "896faa18cd6852ccf977e2dec76191c38f256d031204e233cb3ed76f6088d55b",
            "muid": "239e9199aa"
        },
        "checkpoints/flux1-dev.safetensors": {
            "size": 23802932552,
            "hash": "4610115bb0c89560703c892c59ac2742fa821e60ef5871b33493ba544683abd7",
            "muid": "2f3c5caac0"
        },
        "checkpoints/flux1-schnell.safetensors": {
            "size": 23782506688,
            "hash": "9403429e0052277ac2a87ad800adece5481eecefd9ed334e1f348723621d2a0a",
            "muid": "d314672fc6"
        },
        "checkpoints/flux1-dev-fp8.safetensors": {
            "size": 17246524772,
            "hash": "8e91b68084b53a7fc44ed2a3756d821e355ac1a7b6fe29be760c1db532f3d88a",
            "muid": "7f89b4dd65"
        },
        "checkpoints/flux1-schnell-fp8.safetensors": {
            "size": 17236328572,
            "hash": "ead426278b49030e9da5df862994f25ce94ab2ee4df38b556ddddb3db093bf72",
            "muid": "8f031d049d"
        },
        "checkpoints/FLUX.1-schnell-dev-merged.safetensors": {
            "size": 23802903480,
            "hash": "0dc649761fba58625f57f596738e76422df9424c4c8801ca70c53ad6998c905b",
            "muid": "6661979a94"
        },
        "checkpoints/flux1-schnell-bnb-nf4.safetensors": {
            "size": 11484555394,
            "hash": "e6cba6afca8b2f5599879111e1a5f3dabebe69bcc3ee4a6af46807447adc6d09",
            "muid": "0eaea6dc0d"
        },
        "checkpoints/flux1-dev-bnb-nf4.safetensors": {
            "size": 11489884113,
            "hash": "c5e25d12d720e30a277598ce9ded9db406ee54f63419fe0c801b283d4ea146e2",
            "muid": "6487417fee"
        },
        "checkpoints/hunyuan_dit_1.2.safetensors": {
            "size": 8240228270,
            "hash": "4fb84f84079cda457d171b3c6b15d1be95b5a3e5d9825703951a99ddf92d1787",
            "muid": "8c4c0098ac"
        },
        "checkpoints/juggernaut-X-RunDiffusion-NSFW.safetensors": {
            "size": 7105348672,
            "hash": "d91d35736d8f2be038f760a9b0009a771ecf0a417e9b38c244a84ea4cb9c0c45",
            "muid": "039986f26f01"
        },
        "checkpoints/Juggernaut-XL_v9_RunDiffusionPhoto_v2.safetensors": {
            "size": 7105348188,
            "hash": "c9e3e68f89b8e38689e1097d4be4573cf308de4e3fd044c64ca697bdb4aa8bca",
            "muid": "393f61fcec"
        },
        "checkpoints/playground-v2.5-1024px.safetensors": {
            "size": 6938040576,
            "hash": "bcaa7dd6780974f000b17b5a6c63e6f867a75c51ffa85c67d6b196882c69b992",
            "muid": "d0e21c789d50"
        },
        "checkpoints/ponyDiffusionV6XL.safetensors": {
            "size": 6938041050,
            "hash": "67ab2fd8ec439a89b3fedb15cc65f54336af163c7eb5e4f2acc98f090a29b0b3",
            "muid": "e023c14343"
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
        "loras/Hyper-SDXL-8steps-lora.safetensors": {
            "size": 787359648,
            "hash": "ca689190e8c46038550384b5675488526cfe5a40d35f82b27acb75c100f417c1",
            "muid": "4f494295ed"
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
        "loras/SDXL_FILM_PHOTOGRAPHY_STYLE_V1.safetensors": {
            "size": 912593164,
            "hash": "9e2a98e1f27dbdbb0bda11523dee3444df099599bff7471c6e557f6ad55f27eb",
            "muid": "b39d197db0"
        },
        "loras/sdxl_hyper_sd_4step_lora.safetensors": {
            "size": 787359648,
            "hash": "12f81a27d00a751a40d68fd15597091896c5a90f3bd632fb6c475607cbdad76e",
            "muid": "1c88f7295856"
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
        },
        "diffusers/Kolors/text_encoder/pytorch_model-00001-of-00007.bin": {
            "size": 1827781090,
            "hash": "b6a6388dae55b598efe76c704e7f017bd84e6f6213466b7686a8f8326f78ab05",
            "muid": "b6a6388dae"
        },
        "diffusers/Kolors/text_encoder/pytorch_model-00002-of-00007.bin": {
            "size": 1968299480,
            "hash": "2f96bef324acb5c3fe06b7a80f84272fe064d0327cbf14eddfae7af0d665a6ac",
            "muid": "2f96bef324"
        },
        "diffusers/Kolors/text_encoder/pytorch_model-00003-of-00007.bin": {
            "size": 1927415036,
            "hash": "2400101255213250d9df716f778b7d2325f2fa4a8acaedee788338fceee5b27e",
            "muid": "2400101255"
        },
        "diffusers/Kolors/text_encoder/pytorch_model-00004-of-00007.bin": {
            "size": 1815225998,
            "hash": "472567c1b0e448a19171fbb5b3dab5670426d0a5dfdfd2c3a87a60bb1f96037d",
            "muid": "472567c1b0"
        },
        "diffusers/Kolors/text_encoder/pytorch_model-00005-of-00007.bin": {
            "size": 1968299544,
            "hash": "ef2aea78fa386168958e5ba42ecf09cbb567ed3e77ce2be990d556b84081e2b9",
            "muid": "ef2aea78fa"
        },
        "diffusers/Kolors/text_encoder/pytorch_model-00006-of-00007.bin": {
            "size": 1927415036,
            "hash": "35191adf21a1ab632c2b175fcbb6c27601150026cb1ed5d602938d825954526f",
            "muid": "35191adf21"
        },
        "diffusers/Kolors/text_encoder/pytorch_model-00007-of-00007.bin": {
            "size": 1052808542,
            "hash": "b7cdaa9b8ed183284905c49d19bf42360037fdf2f95acb3093039d3c3a459261",
            "muid": "b7cdaa9b8e"
        },
        "diffusers/Kolors/unet/diffusion_pytorch_model.fp16.safetensors": {
            "size": 5159140240,
            "hash": "425ff1dcbe3a70ac13d3afdd69bd4e3176b0c3260722527c80b210f11d2d966c",
            "muid": "9c8f088e4c"
        },
        "diffusers/Kolors/vae/diffusion_pytorch_model.fp16.safetensors": {
            "size": 167335342,
            "hash": "bcb60880a46b63dea58e9bc591abe15f8350bde47b405f9c38f4be70c6161e68",
            "muid": "345f7343ee"
        },
        "DIFFUSERS/Kolors": {
            "size": 20054,
            "hash": "2eff895bdad33abb2f647c35ccb0c2d70173031effa4f126b335a815442af1e3",
            "muid": "2eff895bda"
        },
        "controlnet/control-lora-canny-rank128.safetensors": {
            "size": 395733680,
            "hash": "56389dbb245ca44de91d662529bd4298abc55ce2318f60bc19454fb72ff68247",
            "muid": "44f83205f6"
        },
        "controlnet/detection_Resnet50_Final.pth": {
            "size": 109497761,
            "hash": "6d1de9c2944f2ccddca5f5e010ea5ae64a39845a86311af6fdf30841b0a5a16d",
            "muid": "6d1de9c294"
        },
        "controlnet/fooocus_ip_negative.safetensors": {
            "size": 65616,
            "hash": "d7caedfb46780825895718c7c8e9ee077e675c935ddfcf272f1c01a4fc8ea72d",
            "muid": "4682603510"
        },
        "controlnet/fooocus_xl_cpds_128.safetensors": {
            "size": 395706528,
            "hash": "eec3fd8209a65b41341ea9f415de66909c97b30fb4d20965b3304e8e5251c2f1",
            "muid": "aa82117d38"
        },
        "controlnet/ip-adapter-plus-face_sdxl_vit-h.bin": {
            "size": 1013454761,
            "hash": "50e886d82940b3c5873d80c2b06d8a4b0d0fccec70bc44fd53f16ac3cfd7fc36",
            "muid": "50e886d829"
        },
        "controlnet/ip-adapter-plus_sdxl_vit-h.bin": {
            "size": 1013454427,
            "hash": "ec70edb7cc8e769c9388d94eeaea3e4526352c9fae793a608782d1d8951fde90",
            "muid": "ec70edb7cc"
        },
        "controlnet/parsing_bisenet.pth": {
            "size": 53289463,
            "hash": "468e13ca13a9b43cc0881a9f99083a430e9c0a38abd935431d1c28ee94b26567",
            "muid": "468e13ca13"
        },
        "controlnet/parsing_parsenet.pth": {
            "size": 85331193,
            "hash": "3d558d8d0e42c20224f13cf5a29c79eba2d59913419f945545d8cf7b72920de2",
            "muid": "3d558d8d0e"
        },
        "inpaint/fooocus_inpaint_head.pth": {
            "size": 52602,
            "hash": "32f7f838e0c6d8f13437ba8411e77a4688d77a2e34df8857e4ef4d51f6b97692",
            "muid": "32f7f838e0"
        },
        "inpaint/groundingdino_swint_ogc.pth": {
            "size": 693997677,
            "hash": "3b3ca2563c77c69f651d7bd133e97139c186df06231157a64c507099c52bc799",
            "muid": "3b3ca2563c"
        },
        "inpaint/sam_vit_b_01ec64.pth": {
            "size": 375042383,
            "hash": "ec2df62732614e57411cdcf32a23ffdf28910380d03139ee0f4fcbe91eb8c912",
            "muid": "ec2df62732"
        },
        "inpaint/sam_vit_h_4b8939.pth": {
            "size": 2564550879,
            "hash": "a7bf3b02f3ebf1267aba913ff637d9a2d5c33d3173bb679e46d9f338c26f262e",
            "muid": "a7bf3b02f3"
        },
        "inpaint/sam_vit_l_0b3195.pth": {
            "size": 1249524607,
            "hash": "3adcc4315b642a4d2101128f611684e8734c41232a17c648ed1693702a49a622",
            "muid": "3adcc4315b"
        },
        "unet/iclight_sd15_fbc_unet_ldm.safetensors": {
            "size": 1719167896,
            "hash": "97a662b8076504e0abad3b3a20b0e91d3312f2a5f19ffcef9059dab6d6679700",
            "muid": "4019c0f83d"
        },
        "unet/iclight_sd15_fc_unet_ldm.safetensors": {
            "size": 1719144856,
            "hash": "9f91f1fc8ad2a2073c5a605fcd70cc70b2e7d2321b30aadca2a247d6490cd780",
            "muid": "f220618ed6"
        },
        "unet/kolors_unet_fp16.safetensors": {
            "size": 5159140240,
            "hash": "425ff1dcbe3a70ac13d3afdd69bd4e3176b0c3260722527c80b210f11d2d966c",
            "muid": "9c8f088e4c"
        },
        "llms/Helsinki-NLP/opus-mt-zh-en/pytorch_model.bin": {
            "size": 312087009,
            "hash": "9d8ceb91d103ef89400c9d9d62328b4858743cf8924878aee3b8afc594242ce0",
            "muid": "9d8ceb91d1"
        },
        "llms/bert-base-uncased/model.safetensors": {
            "size": 440449768,
            "hash": "68d45e234eb4a928074dfd868cead0219ab85354cc53d20e772753c6bb9169d3",
            "muid": "9c02f497ee"
        },
        "llms/nllb-200-distilled-600M/pytorch_model.bin": {
            "size": 2460457927,
            "hash": "c266c2cfd19758b6d09c1fc31ecdf1e485509035f6b51dfe84f1ada83eefcc42",
            "muid": "c266c2cfd1"
        },
        "llms/superprompt-v1/model.safetensors": {
            "size": 307867048,
            "hash": "4f31e59c0582d4a74aac96ffb4ea9f5d64b268564ae5d1f68e8620dc940127d7",
            "muid": "ac31ee526b"
        },
        "vae/ae.safetensors": {
            "size": 335304388,
            "hash": "afc8e28272cd15db3919bacdb6918ce9c1ed22e96cb12c4d5ed0fba823529e38",
            "muid": "ddec9c299f"
        },
        "vae/ponyDiffusionV6XL_vae.safetensors": {
            "size": 334641162,
            "hash": "235745af8d86bf4a4c1b5b4f529868b37019a10f7c0b2e79ad0abca3a22bc6e1",
            "muid": "55f20a1016"
        },
        "vae/sdxl_fp16.vae.safetensors": {
            "size": 167335342,
            "hash": "bcb60880a46b63dea58e9bc591abe15f8350bde47b405f9c38f4be70c6161e68",
            "muid": "345f7343ee"
        },
        "checkpoints/Kolors-Inpainting.safetensors": {
            "size": 5159169040,
            "hash": "235db024626d7291e5d8af6776e8f49fa719c90221da9a54b553bb746101a787",
            "muid": "781857d59e"
        },
        "controlnet/Kolors-ControlNet-Canny.safetensors": {
            "size": 2526129624,
            "hash": "ab34969b4ee57a182deb6e52e15d06c81c5285739caf4db2d8774135fd2b99e7",
            "muid": "0dec730f7e"
        },
        "controlnet/Kolors-ControlNet-Depth.safetensors": {
            "size": 2526129624,
            "hash": "b2e9f9ff67c6c8e3b3fbe833f9596d9d16d456b1911633af9aeb4b80949ee60b",
            "muid": "0ad6e5c573"
        },
        "controlnet/Kolors-ControlNet-Pose.safetensors": {
            "size": 2526129624,
            "hash": "2d21bbb821c903166c7c79f8a3435b51a39fd449cd227f74ac1d345bbc4eb153",
            "muid": "3fdfc617f9"
        },
        "checkpoints/juggernautXL_v8Rundiffusion.safetensors": {
            "size": 7105348592,
            "hash": "aeb7e9e6897a1e58b10494bd989d001e3d4bc9b634633cd7b559838f612c2867",
            "muid": "f84d1c1e05d4"
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
    print(f'[SimpleAI] The path of models_info file: {models_info_path}')

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

def set_scan_models_hash(scan=False):
    ModelsInfo.scan_models_hash = scan
    return


class ModelsInfo:

    scan_models_hash = False

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
                print(f'[ModelInfo] Load model info file {self.info_path} failed!, error:{e}')
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
        #print(f'[ModelInfo] refresh from path:{self.path_map}, model_key:{self.m_info.keys()}')
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
        #print(f'[ModelInfo] new_model_key:{new_model_key}, new_file_key:{new_file_key}')
        for k in self.m_info.keys():
            if k not in new_info_key:
                del_model_key.append(k)
        for f in self.m_file.keys():
            if f not in new_file_key:
                del_file_key.append(f)
        for f in new_model_key:
            f_path = f.split('/')[0]
            file_path = new_model_file[f]
            #print(f'[ModelInfo] Found new model {f} at {file_path}')
            if isinstance(file_path, list):
                file_path = file_path[0]
            if os.path.isdir(file_path):
                size = utils.get_size_subfolders(file_path)
            else:
                size = os.path.getsize(file_path)
            if f in default_models_info.keys() and size == default_models_info[f]["size"]:
                hash = default_models_info[f]["hash"]
                muid = default_models_info[f]["muid"]
            elif ModelsInfo.scan_models_hash:
                print(f'[ModelInfo] Calculate hash for {file_path}')
                if os.path.isdir(file_path):
                    hash = utils.calculate_sha256_subfolder(file_path)
                    muid = hash[:10]
                else:
                    hash = utils.sha256(file_path, length=None)
                    _, file_extension = os.path.splitext(file_path)
                    if file_extension == '.safetensors':
                        print(f'[ModelInfo] Calculate addnet hash for {file_path}')
                        muid = utils.sha256(file_path, use_addnet_hash=True)
                    else:
                        muid = hash[:10]
            else:
                hash = ''
                muid = ''
            self.m_info.update({f:{'size': size, 'hash': hash, 'file': new_model_file[f], 'muid': muid, 'url': ''}})
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
        try:
            with open(self.info_path, "w", encoding="utf-8") as json_file:
                json.dump(self.m_info, json_file, indent=4)
                #print(f'[SimpleAI] Models info update and saved to {self.info_path}.')
        except PermissionError:
            print(f'[SimpleAI] Models info update and save failed: Permission denied, {self.info_path}.')
        except json.JSONDecodeError:
            print(f'[SimpleAI] Models info update and save failed: JSON decode error, {self.info_path}.')
        except Exception as e:
            print(f'[SimpleAI] Models info update and save failed: {e}, {self.info_path}.')

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
        extensions = ['.pth', '.ckpt', '.bin', '.safetensors', '.fooocus.patch', '.sft']
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
