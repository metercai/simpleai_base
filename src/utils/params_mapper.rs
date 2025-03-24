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
    ("seed", "KSampler:main_sampler:seed;TiledKSampler:main_sampler:seed;KolorsSampler:main_sampler:seed;RandomNoise:noise_seed:noise_seed;easy seed:sync_seed:seed;Co_Input_Zho:i2i_overall_input:seed"),
    ("steps", "KSampler:main_sampler:steps;TiledKSampler:main_sampler:steps;KolorsSampler:main_sampler:steps;BasicScheduler:scheduler_select:steps;Co_Input_Zho:i2i_overall_input:steps;easy int:main_steps:value"),
    ("cfg_scale", "KSampler:main_sampler:cfg;TiledKSampler:main_sampler:cfg;KolorsSampler:main_sampler:cfg;CLIPTextEncodeFlux:prompt:guidance;Co_Input_Zho:i2i_overall_input:cfg"),
    ("sampler", "KSampler:main_sampler:sampler_name;TiledKSampler:main_sampler:sampler_name;KSamplerSelect:sampler_select:sampler_name;KSampler Config (rgthree):i2i_KSampler:sampler_name"),
    ("scheduler", "KSampler:main_sampler:scheduler;TiledKSampler:main_sampler:scheduler;KolorsSampler:main_sampler:scheduler;BasicScheduler:scheduler_select:scheduler;KSampler Config (rgthree):i2i_KSampler:scheduler"),
    ("denoise", "KSampler:main_sampler:denoise;TiledKSampler:main_sampler:denoise;KolorsSampler:main_sampler:denoise_strength;BasicScheduler:scheduler_select:denoise;Co_Input_Zho:i2i_overall_input:denoise"),
    ("clip_skip", "Co_Input_Zho:i2i_overall_input:clip_skip"),
    ("tiling", "TiledKSampler:main_sampler:tiling;SeamlessTile:seamless_tile:tiling;CircularVAEDecode:vae_tiled:tiling"),
    ("tiled_offset_x", "OffsetImage:offset_image:x_percent"),
    ("tiled_offset_y", "OffsetImage:offset_image:y_percent"),
    ("base_model", "CheckpointLoaderSimple:base_model:ckpt_name;UNETLoader:base_model:unet_name;CheckpointLoaderNF4:base_model:ckpt_name;UnetLoaderGGUF:base_model:unet_name;MZ_KolorsUNETLoaderV2:base_model:unet_name"),
    ("base_model_dtype", "UNETLoader:base_model:weight_dtype"),
    ("base_model_gguf", "UnetLoaderGGUF:base_model_gguf:unet_name"),
    ("base_model2", "CheckpointLoaderSimple:base_model2:ckpt_name;UNETLoader:base_model2:unet_name"),
    ("base_model2_dtype", "UNETLoader:base_model2:weight_dtype"),
    ("inpaint_model", "UnetLoaderGGUF:inpaint_model:unet_name"),
    ("merge_model", "UNETLoader:merge_model:unet_name"),
    ("model_merge_ratio", "ModelMergeSimple:model_merge_ratio:ratio"),
    ("lora_speedup", "LoraLoaderModelOnly:lora_speedup:lora_name"),
    ("lora_speedup_strength", "LoraLoaderModelOnly:lora_speedup:strength_model"),
    ("lora_1", "LoraLoaderModelOnly:lora_1:lora_name;LoraLoaderModelOnly:lora_speedup:lora_name"),
    ("lora_1_strength", "LoraLoaderModelOnly:lora_1:strength_model;LoraLoaderModelOnly:lora_speedup:strength_model"),
    ("lora_2", "LoraLoaderModelOnly:lora_2:lora_name"),
    ("lora_2_strength", "LoraLoaderModelOnly:lora_2:strength_model"),
    ("lora_3", "LoraLoaderModelOnly:lora_3:lora_name"),
    ("lora_3_strength", "LoraLoaderModelOnly:lora_3:strength_model"),
    ("lora_4", "LoraLoaderModelOnly:lora_4:lora_name"),
    ("lora_4_strength", "LoraLoaderModelOnly:lora_4:strength_model"),
    ("lora_5", "LoraLoaderModelOnly:lora_5:lora_name"),
    ("lora_5_strength", "LoraLoaderModelOnly:lora_5:strength_model"),
    ("width", "EmptyLatentImage:aspect_ratios_size:width;EmptySD3LatentImage:aspect_ratios_size:width;ImageResize+:resize_input_image:width;KolorsSampler:main_sampler:width;easy int:aspect_ratios_width:value;Co_Input_Zho:i2i_overall_input:width"),
    ("height", "EmptyLatentImage:aspect_ratios_size:height;EmptySD3LatentImage:aspect_ratios_size:height;ImageResize+:resize_input_image:height;KolorsSampler:main_sampler:height;easy int:aspect_ratios_height:value;Co_Input_Zho:i2i_overall_input:height"),
    ("prompt", "CLIPTextEncode:prompt:text;MZ_ChatGLM3_V2:prompt:text;KolorsTextEncode:prompt_negative_prompt:prompt;CLIPTextEncodeFlux:prompt:t5xxl;CLIPTextEncodeFlux:prompt:clip_l;Co_Input_Zho:i2i_overall_input:positive"),
    ("negative_prompt", "CLIPTextEncode:negative_prompt:text;MZ_ChatGLM3_V2:negative_prompt:text;KolorsTextEncode:prompt_negative_prompt:negative_prompt;Co_Input_Zho:i2i_overall_input:negative"),
    ("additional_prompt", "easy string:additional_prompt:value"),
    ("clip_model", "DualCLIPLoader:clip_model:clip_name1;DualCLIPLoaderGGUF:clip_model:clip_name1;CLIPLoaderGGUF:clip_model:clip_name;CLIPLoader:clip_model:clip_name;TripleCLIPLoader:clip_model:clip_name1"),
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
    ("wavespeed_strength", "easy float:wavespeed_strength:value"),
    ("i2i_function", "easy int:i2i_function:value"),
    ("i2i_model_type", "easy int:i2i_model_type:value"),
    ("i2i_skip_preprocessors", "easy boolean:i2i_skip_preprocessors:value"),
    ("i2i_ip_image1", "LoadImage:i2i_ip_image1:image"),
    ("i2i_ip_image2", "LoadImage:i2i_ip_image2:image"),
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
    ("i2i_inpaint_image", "LoadImage:i2i_inpaint_image:image"),
    ("i2i_inpaint_mask", "LoadImage:i2i_inpaint_mask:image"),
    ("i2i_inpaint_fn", "easy int:i2i_inpaint_fn:value"),
    ("i2i_inpaint_is_mix_ip", "easy boolean:i2i_inpaint_is_mix_ip:value"),
    ("i2i_inpaint_is_invert_mask", "easy boolean:i2i_inpaint_is_invert_mask:value"),
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
