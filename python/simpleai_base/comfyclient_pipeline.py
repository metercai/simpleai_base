import os
import json
import websocket
import uuid
import random
import httpx
import time
import torch
import numpy as np
import ldm_patched.modules.model_management as model_management
from io import BytesIO
from PIL import Image
import hashlib
import shared
from . import utils


class ComfyInputImage:
    default_image = np.zeros((1024, 1024, 3), dtype=np.uint8)
    default_image_hash = hashlib.sha256(default_image.tobytes()).hexdigest()

    def __init__(self, key_list):
        if not isinstance(key_list, list):
            raise ValueError("key_list must be a list")
        self.map = {}
        for key in key_list:
            self.map[key] = self.default_image
            self.map[f'{key}|hash'] = self.default_image_hash

    def get(self, key):
        return self.map.get(key, None)
    def set_image(self, key, image):
        if isinstance(image, np.ndarray):
            self.map[key] = image
            image_hash = hashlib.sha256(image.tobytes()).hexdigest()
            self.map[f'{key}|hash'] = image_hash
        else:
            raise ValueError("image must be a np.ndarray")

    def set_image_filename(self, key, filename):
        image_hash = self.map[f'{key}|hash']
        self.map[f'{image_hash}|file'] = filename

    def get_image_hash(self, key):
        return self.map[f'{key}|hash']

    def get_image_filename(self, key):
        image_hash = self.map[f'{key}|hash']
        file_key = f'{image_hash}|file'
        return self.map.get(file_key, None)

    def exists(self, key):
        return key in self.map

    def get_key_list(self):
        return [k for k in self.map.keys() if not k.endswith('|hash') and not k.endswith('|file')]

    def len(self):
        return len(self.get_key_list())

def upload_mask(mask):
    with BytesIO() as output:
        mask.save(output)
        output.seek(0)
        files = {'mask': ('mask.jpg', output)}
        data = {'overwrite': 'true', 'type': 'example_type'}
        response = httpx.post("http://{}/upload/mask".format(server_address()), files=files, data=data)
    return response.json()


def queue_prompt(user_did, prompt, user_cert):
    p = {"prompt": prompt, "client_id": user_did, "user_cert": user_cert}
    data = json.dumps(p).encode('utf-8')
    try:
        with httpx.Client() as client:
            response = client.post("http://{}/prompt".format(server_address()), data=data)
            if response.status_code == 200:
                return json.loads(response.read())
            else:
                print(f"Error: {response.status_code} {response.text}")
                return None
    except httpx.RequestError as e:
        print(f"httpx.RequestError: {e}")
        return None


def get_image(filename, subfolder, folder_type):
    params = httpx.QueryParams({
        "filename": filename,
        "subfolder": subfolder,
        "type": folder_type
    })
    with httpx.Client() as client:
        response = client.get(f"http://{server_address()}/view", params=params)
        return response.read()


def get_history(prompt_id):
    with httpx.Client() as client:
        response = client.get("http://{}/history/{}".format(server_address(), prompt_id))
        return json.loads(response.read())


def get_images(user_did, ws, prompt, callback=None, total_steps=None, user_cert=None):
    prompt_id = queue_prompt(user_did, prompt, user_cert)['prompt_id']
    print('[ComfyClient] Request and get ComfyTask_id:{}'.format(prompt_id))
    output_images = {}
    current_node = ''
    total_steps_known = total_steps
    preview_image = None
    current_step = 0
    last_step = 0
    current_total_steps = None
    finished_steps = 0
    while True:
        model_management.throw_exception_if_processing_interrupted()
        try:
            out = ws.recv()
        except ConnectionResetError as e:
            print(f'[ComfyClient] The connect was exception, restart and try again: {e}')
            ws = websocket.WebSocket()
            ws.connect("ws://{}/ws?clientId={}".format(server_address(), user_did))
            out = ws.recv()
        if isinstance(out, str):
            message = json.loads(out)
            current_type = message['type']
            # print(f'current_message={message}')
            if message['type'] == 'executing':
                data = message['data']
                if data['node'] is None and data['prompt_id'] == prompt_id:
                    break
                else:
                    current_node = data['node']
            elif message['type'] == 'progress':
                current_step = message["data"]["value"]
                current_total_steps = message["data"]["max"]
                if total_steps is None:
                    total_steps_known = current_total_steps
        else:
            if current_type == 'progress':
                if prompt[current_node]['class_type'] in \
                        ['KSampler', 'KSamplerAdvanced', 'SamplerCustomAdvanced', 'TiledKSampler','UltimateSDUpscale'] \
                        and callback is not None:
                    preview_image = out[8:]
                    if current_step != last_step:
                        finished_steps += 1
                        callback(finished_steps, total_steps_known, Image.open(BytesIO(preview_image)))
                    last_step = current_step
                if prompt[current_node]['class_type'] == 'SaveImageWebsocket':
                    images_output = output_images.get(prompt[current_node]['_meta']['title'], [])
                    images_output.append(out[8:])
                    output_images[prompt[current_node]['_meta']['title']] = images_output
            continue

    output_images = {k: np.array(Image.open(BytesIO(v[-1]))) for k, v in output_images.items()}
    print(f'[ComfyClient] The ComfyTask:{prompt_id} has finished: {len(output_images)}')
    return output_images


def images_upload(images):
    result = {}
    if images is None or images.len() == 0:
        return result
    for k in images.get_key_list():
        filename = images.get_image_filename(k)
        if filename is None:
            np_image = images.get(k)
            pil_image = Image.fromarray(np_image)
            with BytesIO() as output:
                pil_image.save(output, format="PNG")
                output.seek(0)
                files = {'image': (f'upload_image_{images.get_image_hash(k)[:32]}.png', output)}
                data = {'overwrite': 'true', 'type': 'input'}
                response = httpx.post("http://{}/upload/image".format(server_address()), files=files, data=data)
            filename2 = response.json()["name"]
            images.set_image_filename(k, filename2)
            result.update({k: filename2})
            print(f'[ComfyClient] The ComfyTask:upload_input_image, {k}: {result[k]}')
        else:
            result.update({k: filename})
    return result


def process_flow(user_did, flow_name, params, images, callback=None, total_steps=None, user_cert=None):
    global ws

    if ws is None or ws.status != 101:
        if ws is not None:
            print(f'[ComfyClient] websocket status: {ws.status}, timeout:{ws.timeout}s.')
            ws.close()
        try:
            ws = websocket.WebSocket()
            ws.connect("ws://{}/ws?clientId={}".format(server_address(), user_did))
        except ConnectionRefusedError as e:
            print(f'[ComfyClient] The connect_to_server has failed, sleep and try again: {e}')
            time.sleep(8)
            try:
                ws = websocket.WebSocket()
                ws.connect("ws://{}/ws?clientId={}".format(server_address(), user_did))
            except ConnectionRefusedError as e:
                print(f'[ComfyClient] The connect_to_server has failed, restart and try again: {e}')
                time.sleep(12)
                ws = websocket.WebSocket()
                ws.connect("ws://{}/ws?clientId={}".format(server_address(), user_did))


    images_map = images_upload(images)
    params.update_params(images_map)
    print(f'[ComfyClient] Ready ComfyTask to process: workflow={flow_name}')
    for k, v in params.get_params().items():
        print(f'    {k} = {v}')
    try:
        prompt_str = params.convert2comfy(flow_name)
        if not utils.echo_off:
            print(f'[ComfyClient] ComfyTask prompt: {prompt_str}')
        images = get_images(user_did, ws, prompt_str, callback=callback, total_steps=total_steps, user_cert=user_cert)
        # ws.close()
    except websocket.WebSocketException as e:
        print(f'[ComfyClient] The connect has been closed, restart and try again: {e}')
        ws = None

    imgs = []
    if images:
        images_keys = sorted(images.keys(), reverse=True)
        imgs = [images[key] for key in images_keys]
    else:
        print(f'[ComfyClient] The ComfyTask:{flow_name} has no output images.')
    return imgs


def interrupt():
    try:
        with httpx.Client() as client:
            response = client.post("http://{}/interrupt".format(server_address()))
            return
    except httpx.RequestError as e:
        print(f"httpx.RequestError: {e}")
        return


def free(all=False):
    p = {"unload_models": all == True, "free_memory": True}
    data = json.dumps(p).encode('utf-8')
    try:
        with httpx.Client() as client:
            response = client.post("http://{}/free".format(server_address()), data=data)
            return
    except httpx.RequestError as e:
        print(f"httpx.RequestError: {e}")
        return

def setvars(vars):
    if not vars or not isinstance(vars, dict) or len(vars) == 0:
        return
    p = vars
    data = json.dumps(p).encode('utf-8')
    try:
        with httpx.Client() as client:
            response = client.post("http://{}/setvars".format(server_address()), data=data)
            return
    except httpx.RequestError as e:
        print(f"httpx.RequestError: {e}")
        return


WORKFLOW_DIR = 'workflows'
COMFYUI_ENDPOINT_IP = '127.0.0.1'
COMFYUI_ENDPOINT_PORT = '8187'
server_address = lambda: f'{COMFYUI_ENDPOINT_IP}:{COMFYUI_ENDPOINT_PORT}'
client_id = str(uuid.uuid4())
ws = None
