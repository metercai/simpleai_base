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

    def convert2comfy(self, flow_name):
        return json.loads(self.obj.convert2comfy(flow_name))


