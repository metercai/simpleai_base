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

    const BASEPKG: [(&str, u64); 79] = [
        ("upscale_models/fooocus_upscaler_s409985e5.bin", 33636613),
        ("layer_model/layer_xl_transparent_conv.safetensors", 3619745776),
        ("layer_model/vae_transparent_decoder.safetensors", 208266320),
        ("layer_model/layer_xl_fg2ble.safetensors", 701981624),
        ("llms/Helsinki-NLP/opus-mt-zh-en/source.spm", 804677),
        ("llms/Helsinki-NLP/opus-mt-zh-en/pytorch_model.bin", 312087009),
        ("llms/Helsinki-NLP/opus-mt-zh-en/metadata.json", 1477),
        ("llms/Helsinki-NLP/opus-mt-zh-en/target.spm", 806530),
        ("llms/Helsinki-NLP/opus-mt-zh-en/generation_config.json", 293),
        ("llms/Helsinki-NLP/opus-mt-zh-en/config.json", 1394),
        ("llms/Helsinki-NLP/opus-mt-zh-en/vocab.json", 1617902),
        ("llms/Helsinki-NLP/opus-mt-zh-en/tokenizer_config.json", 44),
        ("llms/superprompt-v1/spiece.model", 791656),
        ("llms/superprompt-v1/README.md", 3661),
        ("llms/superprompt-v1/generation_config.json", 142),
        ("llms/superprompt-v1/config.json", 1512),
        ("llms/superprompt-v1/model.safetensors", 307867048),
        ("llms/superprompt-v1/tokenizer_config.json", 2539),
        ("llms/superprompt-v1/tokenizer.json", 2424064),
        ("llms/bert-base-uncased/config.json", 570),
        ("llms/bert-base-uncased/model.safetensors", 440449768),
        ("llms/bert-base-uncased/vocab.txt", 231508),
        ("llms/bert-base-uncased/tokenizer_config.json", 28),
        ("llms/bert-base-uncased/tokenizer.json", 466062),
        ("unet/iclight_sd15_fc_unet_ldm.safetensors", 1719144856),
        ("clip_vision/wd-v1-4-moat-tagger-v2.onnx", 326197340),
        ("clip_vision/clip_vision_vit_h.safetensors", 1972298538),
        ("clip_vision/model_base_caption_capfilt_large.pth", 896081425),
        ("clip_vision/clip-vit-large-patch14/merges.txt", 524619),
        ("clip_vision/clip-vit-large-patch14/vocab.json", 961143),
        ("clip_vision/clip-vit-large-patch14/special_tokens_map.json", 389),
        ("clip_vision/clip-vit-large-patch14/tokenizer_config.json", 905),
        ("rembg/RMBG-1.4.pth", 176718373),
        ("vae_approx/xlvaeapp.pth", 213777),
        ("vae_approx/xl-to-v1_interposer-v4.0.safetensors", 5667280),
        ("vae_approx/vaeapp_sd15.pth", 213777),
        ("inpaint/groundingdino_swint_ogc.pth", 693997677),
        ("inpaint/isnet-general-use.onnx", 178648008),
        ("inpaint/fooocus_inpaint_head.pth", 52602),
        ("inpaint/u2netp.onnx", 4574861),
        ("inpaint/u2net_human_seg.onnx", 175997641),
        ("inpaint/u2net_cloth_seg.onnx", 176194565),
        ("inpaint/inpaint_v26.fooocus.patch", 1323362033),
        ("inpaint/u2net.onnx", 175997641),
        ("inpaint/sam_vit_b_01ec64.pth", 375042383),
        ("inpaint/silueta.onnx", 44173029),
        ("inpaint/isnet-anime.onnx", 176069933),
        ("checkpoints/realisticVisionV60B1_v51VAE.safetensors", 2132625894),
        ("prompt_expansion/fooocus_expansion/pytorch_model.bin", 351283802),
        ("prompt_expansion/fooocus_expansion/merges.txt", 456356),
        ("prompt_expansion/fooocus_expansion/config.json", 937),
        ("prompt_expansion/fooocus_expansion/vocab.json", 798156),
        ("prompt_expansion/fooocus_expansion/special_tokens_map.json", 99),
        ("prompt_expansion/fooocus_expansion/positive.txt", 5655),
        ("prompt_expansion/fooocus_expansion/tokenizer_config.json", 255),
        ("prompt_expansion/fooocus_expansion/tokenizer.json", 2107625),
        ("loras/ip-adapter-faceid-plusv2_sdxl_lora.safetensors", 371842896),
        ("loras/sdxl_hyper_sd_4step_lora.safetensors", 787359648),
        ("loras/sd_xl_offset_example-lora_1.0.safetensors", 49553604),
        ("loras/sdxl_lightning_4step_lora.safetensors", 393854592),
        ("controlnet/ip-adapter-plus_sdxl_vit-h.bin", 1013454427),
        ("controlnet/fooocus_xl_cpds_128.safetensors", 395706528),
        ("controlnet/parsing_parsenet.pth", 85331193),
        ("controlnet/control-lora-canny-rank128.safetensors", 395733680),
        ("controlnet/detection_Resnet50_Final.pth", 109497761),
        ("controlnet/fooocus_ip_negative.safetensors", 65616),
        ("controlnet/ip-adapter-plus-face_sdxl_vit-h.bin", 1013454761),
        ("configs/v1-inference.yaml", 1873),
        ("configs/v1-inference_clip_skip_2_fp16.yaml", 1956),
        ("configs/v2-inference-v.yaml", 1815),
        ("configs/v2-inference_fp32.yaml", 1790),
        ("configs/anything_v3.yaml", 1933),
        ("configs/v1-inference_fp16.yaml", 1896),
        ("configs/v1-inpainting-inference.yaml", 1992),
        ("configs/v2-inpainting-inference.yaml", 4450),
        ("configs/v1-inference_clip_skip_2.yaml", 1933),
        ("configs/v2-inference-v_fp32.yaml", 1816),
        ("configs/v2-inference.yaml", 1789),
        ("checkpoints/juggernautXL_juggXIByRundiffusion.safetensors", 7105350536),
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

        println!("basepkg: {}, root_path: {}", basepkg.len(), root_path);
        for (filename, size) in basepkg {
            let full_path = Path::new(root_path).join(filename);
            println!("Checking file: {}", full_path.display());
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
