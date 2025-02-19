import json
from simpleai_base.simpleai_base import ComfyTaskParams as inheritedComfyTaskParams

class ComfyTaskParams:
    def __init__(self, params, user_did=""):
        self.obj = inheritedComfyTaskParams(json.dumps(params), user_did)


    def set_mapping_rule(self, maps):
        return self.obj.set_mapping_rule(maps)

    def update_params(self, new_parms):
        return self.obj.update_params(json.dumps(new_parms))

    def delete_params(self, keys):
        return self.obj.delete_params(keys)

    def get_params(self):
        return json.loads(self.obj.get_params())

    def get_rule_key_list(self):
        return self.obj.get_rule_key_list()

    def update_mapping_rule(self, key, value):
        return self.obj.update_mapping_rule(key, value)

    def convert2comfy(self, flow_name):
        return json.loads(self.obj.convert2comfy(flow_name))

    def get_key_mapped(self, workflow):
        return json.loads(self.obj.get_key_mapped(workflow))
