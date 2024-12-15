use std::fs;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::{MAIN_SEPARATOR, Path, PathBuf};
use ripemd::{Ripemd160, Digest};
use sha2::Sha256;
use base58::ToBase58;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;


pub(crate) struct EnvData;

impl EnvData {

    const BASEPKG: [(&'static str, u64); 81] = [
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
        ("clip/clip_l.safetensors", 246144152),
        ("clip_vision/wd-v1-4-moat-tagger-v2.onnx", 326197340),
        ("clip_vision/clip_vision_vit_h.safetensors", 1972298538),
        ("clip_vision/model_base_caption_capfilt_large.pth", 896081425),
        ("clip_vision/clip-vit-large-patch14/merges.txt", 524619),
        ("clip_vision/clip-vit-large-patch14/vocab.json", 961143),
        ("clip_vision/clip-vit-large-patch14/special_tokens_map.json", 389),
        ("clip_vision/clip-vit-large-patch14/tokenizer_config.json", 905),
        ("rembg/RMBG-1.4.pth", 176718373),
        ("vae/ponyDiffusionV6XL_vae.safetensors", 334641162),
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
        ("loras/Hyper-SDXL-8steps-lora.safetensors", 787359648),
        ("loras/sd_xl_offset_example-lora_1.0.safetensors", 49553604),
        ("loras/sdxl_lightning_4step_lora.safetensors", 393854592),
        ("controlnet/xinsir_cn_openpose_sdxl_1.0.safetensors", 2502139104),
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
    ];

    pub fn get_pyhash(v1: &str, v2: &str, v3: &str) -> String {
        let mut pyhash = "Unknown".to_string();
        let log_file_path = Path::new("simplesdxl_log.md");

        if log_file_path.exists() && !v3.ends_with("_dev") {
            if let Ok(file) = File::open(log_file_path) {
                let reader = BufReader::new(file);
                for line in reader.lines() {
                    if let Ok(ln) = line {
                        if ln.starts_with("- ") {
                            let pyhash_line = ln[2..].trim();
                            if pyhash_line.contains('|') {
                                let parts = pyhash_line.split('|');
                                pyhash = parts.last().unwrap_or("").trim().to_string();
                            } else {
                                pyhash = pyhash_line.to_string();
                            }
                            break;
                        }
                    }
                }
            }
        }

        pyhash
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

    pub fn get_check_pyhash(pyhash: &str) -> String {
        let log_file_path = Path::new("simplesdxl_log.md");
        let mut file = File::open(log_file_path).unwrap();
        let mut content = String::new();
        file.read_to_string(&mut content).unwrap();
        let normalized_content = content.replace("\r\n", "\n");
        let file_size = normalized_content.len() as u64;

        let mut hasher = Sha256::new();
        hasher.update(format!("{}-{}", pyhash, file_size));
        let check_hash = hasher.finalize();
        let check_hash_base64 = URL_SAFE_NO_PAD.encode(check_hash);
        check_hash_base64[..10].to_string()
    }


    pub fn check_basepkg(root_path: &str) -> bool {
        let basepkg = EnvData::BASEPKG.iter().map(|(filename, size)| {
            (PathBuf::from(filename), *size)
        }).collect::<Vec<_>>();

        //println!("basepkg: {}, root_path: {}", basepkg.len(), root_path);
        for (filename, size) in basepkg {
            let file_name = filename.to_string_lossy().replace("/", &MAIN_SEPARATOR.to_string());
            let full_path = PathBuf::from(root_path).join(file_name);
            if !full_path.exists() {
                println!("Checking file is not exists / 检测到文件有缺失: {}", full_path.to_string_lossy());
                return false;
            }
            if let Ok(metadata) = fs::metadata(&full_path) {
                let is_text = match full_path.extension().and_then(|ext| ext.to_str()) {
                    Some(ext) if matches!(ext, "txt" | "log" | "py" | "rs" | "toml" | "md") => true,
                    _ => false,
                };
                let mut file_size = metadata.len();
                if is_text {
                    let mut file = File::open(full_path.clone()).unwrap();
                    let mut content = String::new();
                    file.read_to_string(&mut content).unwrap();
                    let normalized_content = content.replace("\r\n", "\n");
                    file_size = normalized_content.len() as u64;
                }
                if file_size != size {
                    println!("Checking file is imperfect / 检测到文件不完整: {}", full_path.to_string_lossy());
                    return false;
                }
            } else {
                return false;
            }
        }
        true
    }
}
