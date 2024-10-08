use std::fs;
use std::rc::Rc;
use std::cell::RefCell;
use std::collections::HashMap;
use serde_json::Value;
use serde_derive::{Serialize, Deserialize};
use pyo3::prelude::*;
use crate::env_utils;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[pyclass]
pub struct ComfyTaskParams {
    params: HashMap<String, Value>,
    fooo2node: HashMap<String, String>,
}

static FOOO2NODE_DATA: &[(&str, &str)] = &[
    ("seed", "KSampler:main_sampler:seed;TiledKSampler:main_sampler:seed;KolorsSampler:main_sampler:seed;RandomNoise:noise_seed:noise_seed;easy seed:sync_seed:seed"),
    ("steps", "KSampler:main_sampler:steps;TiledKSampler:main_sampler:steps;KolorsSampler:main_sampler:steps;BasicScheduler:scheduler_select:steps"),
    ("cfg_scale", "KSampler:main_sampler:cfg;TiledKSampler:main_sampler:cfg;KolorsSampler:main_sampler:cfg;CLIPTextEncodeFlux:prompt:guidance"),
    ("sampler", "KSampler:main_sampler:sampler_name;TiledKSampler:main_sampler:sampler_name;KSamplerSelect:sampler_select:sampler_name"),
    ("scheduler", "KSampler:main_sampler:scheduler;TiledKSampler:main_sampler:scheduler;KolorsSampler:main_sampler:scheduler;BasicScheduler:scheduler_select:scheduler"),
    ("denoise", "KSampler:main_sampler:denoise;TiledKSampler:main_sampler:denoise;KolorsSampler:main_sampler:denoise_strength;BasicScheduler:scheduler_select:denoise"),
    ("tiling", "TiledKSampler:main_sampler:tiling;SeamlessTile:seamless_tile:tiling;CircularVAEDecode:vae_tiled:tiling"),
    ("tiled_offset_x", "OffsetImage:offset_image:x_percent"),
    ("tiled_offset_y", "OffsetImage:offset_image:y_percent"),
    ("base_model", "CheckpointLoaderSimple:base_model:ckpt_name;UNETLoader:base_model:unet_name;CheckpointLoaderNF4:base_model:ckpt_name;UnetLoaderGGUF:base_model:unet_name"),
    ("base_model_dtype", "UNETLoader:base_model:weight_dtype"),
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
    ("width", "EmptyLatentImage:aspect_ratios_size:width;EmptySD3LatentImage:aspect_ratios_size:width;ImageResize+:resize_input_image:width;KolorsSampler:main_sampler:width;easy int:aspect_ratios_width:value"),
    ("height", "EmptyLatentImage:aspect_ratios_size:height;EmptySD3LatentImage:aspect_ratios_size:height;ImageResize+:resize_input_image:height;KolorsSampler:main_sampler:height;easy int:aspect_ratios_height:value"),
    ("prompt", "CLIPTextEncode:prompt:text;MZ_ChatGLM3_V2:prompt:text;KolorsTextEncode:prompt_negative_prompt:prompt;CLIPTextEncodeFlux:prompt:t5xxl;CLIPTextEncodeFlux:prompt:clip_l"),
    ("negative_prompt", "CLIPTextEncode:negative_prompt:text;MZ_ChatGLM3_V2:negative_prompt:text;KolorsTextEncode:prompt_negative_prompt:negative_prompt"),
    ("clip_model", "DualCLIPLoader:clip_model:clip_name1;DualCLIPLoaderGGUF:clip_model:clip_name1;CLIPLoaderGGUF:clip_model:clip_name;CLIPLoader:clip_model:clip_name"),
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
];

#[pymethods]
impl ComfyTaskParams {
    #[new]
    pub fn new(params: String) -> Self {
        let fooo2node: HashMap<String, String> = FOOO2NODE_DATA.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        let params: HashMap<String, Value> = match serde_json::from_str(&params) {
            Ok(json) => json,
            Err(_) => HashMap::new(),
        };
        Self {
            params,
            fooo2node,
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

    pub fn convert2comfy(&self, flow_name: String) -> String {
        let flow_file = env_utils::get_path_in_root_dir("workflows", &format!("{}_api.json", flow_name));
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

/*        let mut node_index = HashMap::new();
        if let Value::Array(nodes) = &mut workflow_json {
            for node in nodes.iter() {
                let class_type = node["class_type"].as_str().unwrap_or_default().to_string();
                let meta_title = node["_meta"]["title"].as_str().unwrap_or_default().to_string();
                let node_ref = Rc::new(RefCell::new(node.clone()));
                node_index.insert((class_type, meta_title), node_ref);
            }
        }
*/
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
                                            node["inputs"][keys[i]] = Value::String(vs[i].to_string());
                                        }
                                    }
                                } else {
                                    node["inputs"][inputs.clone()] = v.clone();
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

}
