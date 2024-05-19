
class ComfyTaskParams:
    def __init__(self, params):
        self.params = params
        self.workflow = ''

    fooo2node = {
        'seed': 'KSampler:main_sampler:seed',
        'steps': 'KSampler:main_sampler:steps',
        'cfg_scale': 'KSampler:main_sampler:cfg',
        'sampler': 'KSampler:main_sampler:sampler_name',
        'scheduler': 'KSampler:main_sampler:scheduler',
        'denoise': 'KSampler:main_sampler:denoise',
        'base_model': 'CheckpointLoaderSimple:base_model:ckpt_name',
        'width': 'EmptyLatentImage:aspect_ratios_size:width;ImageResize:resize_input_image:width',
        'height': 'EmptyLatentImage:aspect_ratios_size:height;ImageResize:resize_input_image:height',
        'prompt': 'CLIPTextEncode:prompt:text',
        'negative_prompt': 'CLIPTextEncode:negative_prompt:text',
        'input_image': 'LoadImage:input_image:image',
        'layer_diffuse_injection': 'LayeredDiffusionApply:layer_diffuse_apply:config',
        'sd_version': 'LayeredDiffusionDecode:layer_diffuse_decode:sd_version;LayeredDiffusionDecodeRGBA:layer_diffuse_decode_rgba:sd_version',
        'layer_diffuse_cond': 'LayeredDiffusionCondApply:layer_diffuse_cond_apply:config'
        }

    def set_mapping_rule(self, maps):
        self.fooo2node.update(maps)

    def update_params(self, new_parms):
        self.params.update(new_parms)

    def convert2comfy(self, workflow):
        #print(f'params:{self.params}')
        self.workflow = workflow
        for (pk1,v) in self.params.items():
            nk = self.fooo2node[pk1]
            self.replace_key(nk,v)
        return self.workflow


    def replace_key(self,nk,v):
        lines = nk.split(';')
        for line in lines:
            parts = line.strip().split(':')
            class_type = parts[0].strip()
            meta_title = parts[1].strip()
            inputs = parts[2].strip()
            for n in self.workflow.keys():
                if self.workflow[n]["class_type"]==class_type and self.workflow[n]["_meta"]["title"]==meta_title:
                    if '|' in inputs:
                        keys = inputs.split('|')
                        vs = v.strip().split('|')
                        for i in range(len(keys)):
                            self.workflow[n]["inputs"][keys[i]] = vs[i]
                    else:
                        self.workflow[n]["inputs"][inputs] = v
    


