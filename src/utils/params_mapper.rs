use std::fs;
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use serde_json::Value;
use serde::{Serialize, Deserialize};
use pyo3::prelude::*;
use crate::dids::token_utils;
use crate::user::TokenUser;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[pyclass]
pub struct ComfyTaskParams {
    params: HashMap<String, Value>,
    fooo2node: HashMap<String, String>,
    user_did: String,
}

static FOOO2NODE_DATA: &[(&str, &str)] = &[
    ("seed", "KSampler:main_sampler:seed;TiledKSampler:main_sampler:seed;KolorsSampler:main_sampler:seed;RandomNoise:noise_seed:noise_seed;easy seed:sync_seed:seed;Co_Input_Zho:i2i_overall_input:seed;SeedInput:SeedInput:seed"),
    ("steps", "KSampler:main_sampler:steps;TiledKSampler:main_sampler:steps;KolorsSampler:main_sampler:steps;BasicScheduler:scheduler_select:steps;Co_Input_Zho:i2i_overall_input:steps;easy int:main_steps:value;GeneralInput:GeneralInput:steps"),
    ("cfg_scale", "KSampler:main_sampler:cfg;TiledKSampler:main_sampler:cfg;KolorsSampler:main_sampler:cfg;CLIPTextEncodeFlux:prompt:guidance;Co_Input_Zho:i2i_overall_input:cfg;GeneralInput:GeneralInput:cfg"),
    ("sampler", "KSampler:main_sampler:sampler_name;TiledKSampler:main_sampler:sampler_name;KSamplerSelect:sampler_select:sampler_name;KSampler Config (rgthree):i2i_KSampler:sampler_name"),
    ("scheduler", "KSampler:main_sampler:scheduler;TiledKSampler:main_sampler:scheduler;KolorsSampler:main_sampler:scheduler;BasicScheduler:scheduler_select:scheduler;KSampler Config (rgthree):i2i_KSampler:scheduler"),
    ("denoise", "KSampler:main_sampler:denoise;TiledKSampler:main_sampler:denoise;KolorsSampler:main_sampler:denoise_strength;BasicScheduler:scheduler_select:denoise;Co_Input_Zho:i2i_overall_input:denoise;GeneralInput:GeneralInput:denoise"),
    ("clip_skip", "Co_Input_Zho:i2i_overall_input:clip_skip;GeneralInput:GeneralInput:clip_skip"),
    ("tiling", "TiledKSampler:main_sampler:tiling;SeamlessTile:seamless_tile:tiling;CircularVAEDecode:vae_tiled:tiling"),
    ("tiled_offset_x", "OffsetImage:offset_image:x_percent"),
    ("tiled_offset_y", "OffsetImage:offset_image:y_percent"),
    ("base_model", "CheckpointLoaderSimple:base_model:ckpt_name;UNETLoader:UNETLoader:unet_name;UNETLoader:base_model:unet_name;CheckpointLoaderNF4:base_model:ckpt_name;UnetLoaderGGUF:base_model:unet_name;MZ_KolorsUNETLoaderV2:base_model:unet_name;WanVideoModelLoader:WanVideoModelLoader:model;LoadFramePackModel:LoadFramePackModel:model"),
    ("base_model_dtype", "UNETLoader:base_model:weight_dtype"),
    ("base_model_gguf", "UnetLoaderGGUF:base_model_gguf:unet_name"),
    ("base_model2", "CheckpointLoaderSimple:base_model2:ckpt_name;UNETLoader:UNETLoader2:unet_name;UNETLoader:base_model2:unet_name"),
    ("base_model2_dtype", "UNETLoader:base_model2:weight_dtype"),
    ("inpaint_model", "UnetLoaderGGUF:inpaint_model:unet_name"),
    ("merge_model", "UNETLoader:merge_model:unet_name"),
    ("model_merge_ratio", "ModelMergeSimple:model_merge_ratio:ratio"),
    ("refiner_step", "GeneralInput:GeneralInput:refiner_step"),
    ("lora_speedup", "LoraLoaderModelOnly:lora_speedup:lora_name"),
    ("lora_speedup_strength", "LoraLoaderModelOnly:lora_speedup:strength_model"),
    ("lora_1", "LoraLoaderModelOnly:LoraLoaderModelOnly1:lora_name;LoraLoaderModelOnly:lora_1:lora_name;LoraLoaderModelOnly:lora_speedup:lora_name;NunchakuFluxLoraLoader:NunchakuFluxLoraLoader1:lora_name;WanVideoLoraSelect:WanVideoLoraSelect1:lora;FramePackLoraSelect:FramePackLoraSelect1:lora"),
    ("lora_1_strength", "LoraLoaderModelOnly:LoraLoaderModelOnly1:strength_model;LoraLoaderModelOnly:lora_1:strength_model;LoraLoaderModelOnly:lora_speedup:strength_model;NunchakuFluxLoraLoader:NunchakuFluxLoraLoader1:lora_strength;WanVideoLoraSelect:WanVideoLoraSelect1:strength;FramePackLoraSelect:FramePackLoraSelect1:strength"),
    ("lora_2", "LoraLoaderModelOnly:LoraLoaderModelOnly2:lora_name;LoraLoaderModelOnly:lora_2:lora_name;NunchakuFluxLoraLoader:NunchakuFluxLoraLoader2:lora_name;WanVideoLoraSelect:WanVideoLoraSelect2:lora;FramePackLoraSelect:FramePackLoraSelect2:lora"),
    ("lora_2_strength", "LoraLoaderModelOnly:LoraLoaderModelOnly2:strength_model;LoraLoaderModelOnly:lora_2:strength_model;NunchakuFluxLoraLoader:NunchakuFluxLoraLoader2:lora_strength;WanVideoLoraSelect:WanVideoLoraSelect2:strength;FramePackLoraSelect:FramePackLoraSelect2:strength"),
    ("lora_3", "LoraLoaderModelOnly:LoraLoaderModelOnly3:lora_name;LoraLoaderModelOnly:lora_3:lora_name;NunchakuFluxLoraLoader:NunchakuFluxLoraLoader3:lora_name;WanVideoLoraSelect:WanVideoLoraSelect3:lora;FramePackLoraSelect:FramePackLoraSelect3:lora"),
    ("lora_3_strength", "LoraLoaderModelOnly:LoraLoaderModelOnly3:strength_model;LoraLoaderModelOnly:lora_3:strength_model;NunchakuFluxLoraLoader:NunchakuFluxLoraLoader3:lora_strength;WanVideoLoraSelect:WanVideoLoraSelect3:strength;FramePackLoraSelect:FramePackLoraSelect3:strength"),
    ("lora_4", "LoraLoaderModelOnly:LoraLoaderModelOnly4:lora_name;LoraLoaderModelOnly:lora_4:lora_name;NunchakuFluxLoraLoader:NunchakuFluxLoraLoader4:lora_name;WanVideoLoraSelect:WanVideoLoraSelect4:lora;FramePackLoraSelect:FramePackLoraSelect4:lora"),
    ("lora_4_strength", "LoraLoaderModelOnly:LoraLoaderModelOnly4:strength_model;LoraLoaderModelOnly:lora_4:strength_model;NunchakuFluxLoraLoader:NunchakuFluxLoraLoader4:lora_strength;WanVideoLoraSelect:WanVideoLoraSelect4:strength;FramePackLoraSelect:FramePackLoraSelect4:strength"),
    ("lora_5", "LoraLoaderModelOnly:LoraLoaderModelOnly5:lora_name;LoraLoaderModelOnly:lora_5:lora_name;NunchakuFluxLoraLoader:NunchakuFluxLoraLoader5:lora_name;WanVideoLoraSelect:WanVideoLoraSelect5:lora;FramePackLoraSelect:FramePackLoraSelect5:lora"),
    ("lora_5_strength", "LoraLoaderModelOnly:LoraLoaderModelOnly5:strength_model;LoraLoaderModelOnly:lora_5:strength_model;NunchakuFluxLoraLoader:NunchakuFluxLoraLoader5:lora_strength;WanVideoLoraSelect:WanVideoLoraSelect5:strength;FramePackLoraSelect:FramePackLoraSelect5:strength"),
    ("width", "EmptyLatentImage:aspect_ratios_size:width;EmptySD3LatentImage:aspect_ratios_size:width;ImageResize+:resize_input_image:width;KolorsSampler:main_sampler:width;easy int:aspect_ratios_width:value;Co_Input_Zho:i2i_overall_input:width;GeneralInput:GeneralInput:width;SceneInput:SceneInput:width"),
    ("height", "EmptyLatentImage:aspect_ratios_size:height;EmptySD3LatentImage:aspect_ratios_size:height;ImageResize+:resize_input_image:height;KolorsSampler:main_sampler:height;easy int:aspect_ratios_height:value;Co_Input_Zho:i2i_overall_input:height;GeneralInput:GeneralInput:height;SceneInput:SceneInput:height"),
    ("prompt", "CLIPTextEncode:prompt:text;CLIPTextEncode:prompt:text;MZ_ChatGLM3_V2:prompt:text;KolorsTextEncode:prompt_negative_prompt:prompt;CLIPTextEncodeFlux:prompt:t5xxl;CLIPTextEncodeFlux:prompt:clip_l;Co_Input_Zho:i2i_overall_input:positive;GeneralInput:GeneralInput:prompt;SceneInput:SceneInput:prompt"),
    ("negative_prompt", "CLIPTextEncode:negative_prompt:text;MZ_ChatGLM3_V2:negative_prompt:text;KolorsTextEncode:prompt_negative_prompt:negative_prompt;Co_Input_Zho:i2i_overall_input:negative;GeneralInput:GeneralInput:negative_prompt"),
    ("additional_prompt", "easy string:additional_prompt:value;SceneInput:SceneInput:additional_prompt"),
    ("clip_model", "DualCLIPLoader:clip_model:clip_name1;DualCLIPLoaderGGUF:DualCLIPLoaderGGUF:clip_name1;DualCLIPLoaderGGUF:clip_model:clip_name1;CLIPLoaderGGUF:CLIPLoaderGGUF:clip_name;CLIPLoaderGGUF:clip_model:clip_name;CLIPLoader:CLIPLoader:clip_name;CLIPLoader:clip_model:clip_name;TripleCLIPLoader:TripleCLIPLoader:clip_name1;TripleCLIPLoader:clip_model:clip_name1"),
    ("clip_model2", "TripleCLIPLoader:clip_model:clip_name2"),
    ("vae_model", "VAELoader:vae_model:vae_name"),
    ("is_custom_vae", "easy boolean:is_custom_vae:value"),
    ("llms_model", "MZ_ChatGLM3Loader:llms_model:chatglm3_checkpoint;DownloadAndLoadChatGLM3:llms_model:precision"),
    ("input_image", "LoadImage:input_image:image"),
    ("layer_diffuse_injection", "LayeredDiffusionApply:layer_diffuse_apply:config"),
    ("sd_version", "LayeredDiffusionDecode:layer_diffuse_decode:sd_version;LayeredDiffusionDecodeRGBA:layer_diffuse_decode_rgba:sd_version"),
    ("layer_diffuse_cond", "LayeredDiffusionCondApply:layer_diffuse_cond_apply:config"),
    ("light_source_text_switch", "easy imageSwitch:ic_light_source_text_switch:boolean"),
    ("light_source_shape_switch", "easy imageSwitch:ic_light_source_shape_switch:boolean"),
    ("light_source_text", "LightSource:ic_light_source_text:light_position"),
    ("light_apply", "LoadAndApplyICLightUnet:ic_light_apply:model_path"),
    ("light_detail_transfer", "DetailTransfer:ic_light_detail_transfer:mode"),
    ("light_source_start_color", "CreateGradientFromCoords:ic_light_source_color:start_color"),
    ("light_source_end_color", "CreateGradientFromCoords:ic_light_source_color:end_color"),
    ("light_editor_path", "SplineEditor:ic_light_editor:points_store"),
    ("wavespeed_strength", "easy float:wavespeed_strength:value;GeneralInput:GeneralInput:wavespeed_strength"),
    ("var_number", "easy int:var_number:value;SceneInput:SceneInput:var_number"),
    ("i2i_function", "easy int:i2i_function:value"),
    ("i2i_model_type", "easy int:i2i_model_type:value"),
    ("i2i_skip_preprocessors", "easy boolean:i2i_skip_preprocessors:value"),
    ("i2i_ip_image1", "LoadImage:i2i_ip_image1:image;SceneInput:SceneInput:ip_image"),
    ("i2i_ip_image2", "LoadImage:i2i_ip_image2:image;SceneInput:SceneInput:ip_image1"),
    ("i2i_ip_image3", "LoadImage:i2i_ip_image3:image"),
    ("i2i_ip_image4", "LoadImage:i2i_ip_image4:image"),
    ("i2i_ip_fn1", "easy int:i2i_ip_fn1:value"),
    ("i2i_ip_fn2", "easy int:i2i_ip_fn2:value"),
    ("i2i_ip_fn3", "easy int:i2i_ip_fn3:value"),
    ("i2i_ip_fn4", "easy int:i2i_ip_fn4:value"),
    ("i2i_ip_fn1_w", "easy float:i2i_ip_fn1_w:value"),
    ("i2i_ip_fn2_w", "easy float:i2i_ip_fn2_w:value"),
    ("i2i_ip_fn3_w", "easy float:i2i_ip_fn3_w:value"),
    ("i2i_ip_fn4_w", "easy float:i2i_ip_fn4_w:value"),
    ("i2i_ip_fn1_s", "easy float:i2i_ip_fn1_s:value"),
    ("i2i_ip_fn2_s", "easy float:i2i_ip_fn2_s:value"),
    ("i2i_ip_fn3_s", "easy float:i2i_ip_fn3_s:value"),
    ("i2i_ip_fn4_s", "easy float:i2i_ip_fn4_s:value"),
    ("i2i_uov_image", "LoadImage:i2i_uov_image:image"),
    ("i2i_uov_fn", "easy int:i2i_uov_fn:value"),
    ("i2i_uov_is_mix_ip", "easy boolean:i2i_uov_is_mix_ip:value"),
    ("i2i_uov_tiled_width", "easy int:i2i_uov_tiled_width:value"),
    ("i2i_uov_tiled_height", "easy int:i2i_uov_tiled_height:value"),
    ("i2i_uov_tiled_steps", "easy int:i2i_uov_tiled_steps:value"),
    ("i2i_uov_multiple", "easy float:i2i_uov_multiple:value"),
    ("i2i_uov_hires_fix_blurred", "easy float:i2i_uov_hires_fix_blurred:value"),
    ("i2i_uov_hires_fix_w", "easy float:i2i_uov_hires_fix_w:value"),
    ("i2i_uov_hires_fix_s", "easy float:i2i_uov_hires_fix_s:value"),
    ("i2i_inpaint_version", "easy string:i2i_inpaint_version:value"),
    ("i2i_inpaint_image", "LoadImage:i2i_inpaint_image:image;SceneInput:SceneInput:inpaint_image"),
    ("i2i_inpaint_mask", "LoadImage:i2i_inpaint_mask:image;SceneInput:SceneInput:inpaint_mask"),
    ("i2i_inpaint_fn", "easy int:i2i_inpaint_fn:value"),
    ("i2i_inpaint_is_mix_ip", "easy boolean:i2i_inpaint_is_mix_ip:value"),
    ("i2i_inpaint_is_invert_mask", "easy boolean:i2i_inpaint_is_invert_mask:value"),
    ("i2i_inpaint_disable_initial_latent", "GeneralInput:GeneralInput:inpaint_disable_initial_latent"),
    ("enhance_uov_method", "EnhanceUovInput:EnhanceUovInput:uov_method"),
    ("enhance_uov_prompt_type", "EnhanceUovInput:EnhanceUovInput:uov_prompt_type"),
    ("enhance_prompt", "EnhanceRegionInput:EnhanceRegionInput:prompt"),
    ("enhance_negative_prompt", "EnhanceRegionInput:EnhanceRegionInput:negative_prompt"),
    ("enhance_mask_dino_prompt_text", "EnhanceRegionInput:EnhanceRegionInput:mask_dino_prompt_text"),
    ("enhance_mask_model", "EnhanceRegionInput:EnhanceRegionInput:mask_model"),
    ("enhance_mask_cloth_category", "EnhanceRegionInput:EnhanceRegionInput:mask_cloth_category"),
    ("enhance_mask_sam_model", "EnhanceRegionInput:EnhanceRegionInput:mask_sam_model"),
    ("enhance_mask_text_threshold", "EnhanceRegionInput:EnhanceRegionInput:mask_text_threshold"),
    ("enhance_mask_box_threshold", "EnhanceRegionInput:EnhanceRegionInput:mask_box_threshold"),
    ("enhance_mask_sam_max_detections", "EnhanceRegionInput:EnhanceRegionInput:mask_sam_max_detections"),
    ("enhance_mask_invert", "EnhanceRegionInput:EnhanceRegionInput:mask_invert"),
    ("enhance_inpaint_disable_initial_latent", "EnhanceRegionInput:EnhanceRegionInput:inpaint_disable_initial_latent"),
    ("enhance_inpaint_engine", "EnhanceRegionInput:EnhanceRegionInput:inpaint_engine"),
    ("enhance_inpaint_strength", "EnhanceRegionInput:EnhanceRegionInput:inpaint_strength"),
    ("enhance_inpaint_respective_field", "EnhanceRegionInput:EnhanceRegionInput:inpaint_respective_field"),
    ("enhance_inpaint_erode_or_dilate", "EnhanceRegionInput:EnhanceRegionInput:inpaint_erode_or_dilate"),
    ("enhance_prompt1", "EnhanceRegionInput:EnhanceRegionInput1:prompt"),
    ("enhance_negative_prompt1", "EnhanceRegionInput:EnhanceRegionInput1:negative_prompt"),
    ("enhance_mask_dino_prompt_text1", "EnhanceRegionInput:EnhanceRegionInput1:mask_dino_prompt_text"),
    ("enhance_mask_model1", "EnhanceRegionInput:EnhanceRegionInput1:mask_model"),
    ("enhance_mask_cloth_category1", "EnhanceRegionInput:EnhanceRegionInput1:mask_cloth_category"),
    ("enhance_mask_sam_model1", "EnhanceRegionInput:EnhanceRegionInput1:mask_sam_model"),
    ("enhance_mask_text_threshold1", "EnhanceRegionInput:EnhanceRegionInput1:mask_text_threshold"),
    ("enhance_mask_box_threshold1", "EnhanceRegionInput:EnhanceRegionInput1:mask_box_threshold"),
    ("enhance_mask_sam_max_detections1", "EnhanceRegionInput:EnhanceRegionInput1:mask_sam_max_detections"),
    ("enhance_mask_invert1", "EnhanceRegionInput:EnhanceRegionInput1:mask_invert"),
    ("enhance_inpaint_disable_initial_latent1", "EnhanceRegionInput:EnhanceRegionInput1:inpaint_disable_initial_latent"),
    ("enhance_inpaint_engine1", "EnhanceRegionInput:EnhanceRegionInput1:inpaint_engine"),
    ("enhance_inpaint_strength1", "EnhanceRegionInput:EnhanceRegionInput1:inpaint_strength"),
    ("enhance_inpaint_respective_field1", "EnhanceRegionInput:EnhanceRegionInput1:inpaint_respective_field"),
    ("enhance_inpaint_erode_or_dilate1", "EnhanceRegionInput:EnhanceRegionInput1:inpaint_erode_or_dilate"),
    ("enhance_prompt2", "EnhanceRegionInput:EnhanceRegionInput2:prompt"),
    ("enhance_negative_prompt2", "EnhanceRegionInput:EnhanceRegionInput2:negative_prompt"),
    ("enhance_mask_dino_prompt_text2", "EnhanceRegionInput:EnhanceRegionInput2:mask_dino_prompt_text"),
    ("enhance_mask_model2", "EnhanceRegionInput:EnhanceRegionInput2:mask_model"),
    ("enhance_mask_cloth_category2", "EnhanceRegionInput:EnhanceRegionInput2:mask_cloth_category"),
    ("enhance_mask_sam_model2", "EnhanceRegionInput:EnhanceRegionInput2:mask_sam_model"),
    ("enhance_mask_text_threshold2", "EnhanceRegionInput:EnhanceRegionInput2:mask_text_threshold"),
    ("enhance_mask_box_threshold2", "EnhanceRegionInput:EnhanceRegionInput2:mask_box_threshold"),
    ("enhance_mask_sam_max_detections2", "EnhanceRegionInput:EnhanceRegionInput2:mask_sam_max_detections"),
    ("enhance_mask_invert2", "EnhanceRegionInput:EnhanceRegionInput2:mask_invert"),
    ("enhance_inpaint_disable_initial_latent2", "EnhanceRegionInput2:EnhanceRegionInput:inpaint_disable_initial_latent"),
    ("enhance_inpaint_engine2", "EnhanceRegionInput:EnhanceRegionInput2:inpaint_engine"),
    ("enhance_inpaint_strength2", "EnhanceRegionInput:EnhanceRegionInput2:inpaint_strength"),
    ("enhance_inpaint_respective_field2", "EnhanceRegionInput:EnhanceRegionInput2:inpaint_respective_field"),
    ("enhance_inpaint_erode_or_dilate2", "EnhanceRegionInput:EnhanceRegionInput2:inpaint_erode_or_dilate"),
    
];

#[pymethods]
impl ComfyTaskParams {
    #[new]
    pub fn new(params: String, user_did: String) -> Self {
        let fooo2node: HashMap<String, String> = FOOO2NODE_DATA.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        let params: HashMap<String, Value> = match serde_json::from_str(&params) {
            Ok(json) => json,
            Err(_) => HashMap::new(),
        };
        Self {
            params,
            fooo2node,
            user_did
        }
    }

    pub fn set_mapping_rule(&mut self, maps: HashMap<String, String>) {
        self.fooo2node.extend(maps);
    }

    pub fn update_params(&mut self, new_params: String) {
        let new_params: HashMap<String, Value> = match serde_json::from_str(&new_params) {
            Ok(json) => json,
            Err(_) => HashMap::new(),
        };
        self.params.extend(new_params);
    }

    pub fn delete_params(&mut self, keys: Vec<String>) {
        for k in keys {
            self.params.remove(&k);
        }
    }

    pub fn get_params(&self) -> String {
        match serde_json::to_string(&self.params) {
            Ok(json_string) => json_string,
            Err(e) => {
                println!("Error converting params to JSON string: {}", e);
                "{}".to_string()
            }
        }
    }

    pub fn get_rule_key_list(&self) -> Vec<String> {
        self.fooo2node.keys().cloned().collect()
    }

    pub fn update_mapping_rule(&mut self, key: String, value: String) {
        if let Some(existing) = self.fooo2node.get_mut(&key) {
            if !existing.is_empty() {
                existing.push_str(";");
            }
            existing.push_str(&value);
        } else {
            self.fooo2node.insert(key, value);
        }
    }

    pub fn convert2comfy(&self, flow_name: String) -> String {
        let filename = format!("{}_api.json", flow_name);
        let filename_with_path = format!("workflows/{}", filename);
        let flow_file = {
            let tokenuser = TokenUser::instance();
            let tokenuser = tokenuser.lock().unwrap();
            tokenuser.get_path_in_user_dir(&self.user_did, &filename_with_path)
        };
        let flow_file = Path::new(&flow_file);
        let flow_file = match flow_file.exists() {
            true => PathBuf::from(flow_file),
            false => token_utils::get_path_in_root_dir("workflows", &filename)
        };

        let workflow = match fs::read_to_string(flow_file) {
            Ok(json_str) => json_str,
            Err(e) => {
                println!("Error reading file: {}", e);
                "{}".to_string()
            }
        };

        let mut workflow_json: Value = match serde_json::from_str(&workflow) {
            Ok(json) => json,
            Err(e) => {
                eprintln!("Error parsing JSON: {}\nInput JSON: {}", e, workflow);
                return workflow.to_string();
            }
        };


        for (pk1, v) in &self.params {
            if let Some(nk) = self.fooo2node.get(pk1) {
                for line in nk.split(';') {
                    let parts: Vec<&str> = line.trim().split(':').collect();
                    let class_type = parts[0].trim().to_string();
                    let meta_title = parts[1].trim().to_string();
                    let inputs = parts[2].trim().to_string();
                    if let Value::Object(ref mut nodes) = workflow_json {
                        for (_k, node) in nodes.iter_mut() {
                            if node["class_type"] == class_type && node["_meta"]["title"] == meta_title {
                                if inputs.contains('|') { // one node and multiple params
                                    let keys: Vec<&str> = inputs.split('|').collect();
                                    if let Value::String(vs) = v {
                                        let vs: Vec<&str> = vs.trim().split('|').collect();
                                        for i in 0..keys.len() {
                                            if node["inputs"].get(keys[i]).is_some() {
                                                node["inputs"][keys[i]] = Value::String(vs[i].to_string());
                                            }
                                        }
                                    }
                                } else {
                                    if node["inputs"].get(inputs.as_str()).is_some() {
                                        node["inputs"][inputs.clone()] = v.clone();
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        match serde_json::to_string(&workflow_json) {
            Ok(new_workflow) => new_workflow,
            Err(e) => {
                println!("Error converting JSON to string: {}\nJSON: {}", e, workflow_json);
                workflow.to_string()
            }
        }
    }

    pub fn get_key_mapped(&self, workflow: String) -> HashMap<String, Vec<String>> {
        let workflow_json: Value = match serde_json::from_str(&workflow) {
            Ok(json) => json,
            Err(_) => return HashMap::new(),
        };

        let mut result: HashMap<String, Vec<String>> = HashMap::new();
        for (key, mapping) in &self.fooo2node {
            for line in mapping.split(';') {
                let parts: Vec<&str> = line.trim().split(':').collect();
                if parts.len() != 3 {
                    continue;
                }
                let (class_type, meta_title, inputs_value) = (parts[0], parts[1], parts[2]);

                if let Value::Object(nodes) = &workflow_json {
                    for (_, node) in nodes {
                        let node_class = node["class_type"].as_str().unwrap_or_default();
                        let node_title = node["_meta"]["title"].as_str().unwrap_or_default();
                        if node_class == class_type && node_title == meta_title {
                            if let Some(inputs) = node["inputs"].as_object() {
                                if inputs.contains_key(inputs_value) {
                                    result.entry(key.clone()).or_insert_with(Vec::new).push(line.trim().to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
        result
    }

}
