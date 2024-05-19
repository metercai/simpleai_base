import os
import json
import websocket 
import uuid
import random
import httpx
import numpy as np
from io import BytesIO
from PIL import Image

def upload_mask(mask):
    with BytesIO() as output:
        mask.save(output)
        output.seek(0)
        files = {'mask': ('mask.jpg', output)}
        data = {'overwrite': 'true', 'type': 'example_type'}
        response = httpx.post("http://{}/upload/mask".format(server_address), files=files, data=data)
    return response.json()

def queue_prompt(prompt):
    p = {"prompt": prompt, "client_id": client_id}
    data = json.dumps(p).encode('utf-8')
    with httpx.Client() as client:
        response = client.post("http://{}/prompt".format(server_address), data=data)
        return json.loads(response.read())

def get_image(filename, subfolder, folder_type):
    params = httpx.QueryParams({
        "filename": filename,
        "subfolder": subfolder,
        "type": folder_type
    })
    with httpx.Client() as client:
        response = client.get(f"http://{server_address}/view", params=params)
        return response.read()

def get_history(prompt_id):
    with httpx.Client() as client:
        response = client.get("http://{}/history/{}".format(server_address, prompt_id))
        return json.loads(response.read())

def get_images(ws, prompt, callback=None):
    prompt_id = queue_prompt(prompt)['prompt_id']
    print('[ComfyClient] Request and get ComfyTask_id:{}'.format(prompt_id))
    output_images = {}
    current_node = ''
    last_node = None
    preview_image = []
    last_step = None
    current_step = None
    current_total_steps = None
    while True:
        out = ws.recv()
        if isinstance(out, str):
            message = json.loads(out)
            current_type = message['type']
            #print(f'current_message={message}')
            if message['type'] == 'executing':
                data = message['data']
                if data['node'] is None and data['prompt_id'] == prompt_id:
                    break
                else:
                    current_node = data['node']
            elif message['type'] == 'progress':
                current_step = message["data"]["value"]
                current_total_steps = message["data"]["max"]
        else:
            if current_type == 'progress':
                if 'KSampler' in prompt[current_node]['class_type'] and callback is not None:
                    if current_step == last_step:
                        preview_image.append(out[8:])
                    else:
                        if last_step is not None:
                            callback(last_step, current_total_steps, Image.open(BytesIO(preview_image[0])))
                        preview_image = []
                        preview_image.append(out[8:])
                        last_step = current_step
                if prompt[current_node]['class_type'] == 'SaveImageWebsocket':
                    images_output = output_images.get(prompt[current_node]['_meta']['title'], [])
                    images_output.append(out[8:])
                    output_images[prompt[current_node]['_meta']['title']] = images_output[0]
            continue  

    output_images = {k: np.array(Image.open(BytesIO(v))) for k, v in output_images.items()}
    print(f'[ComfyClient] The ComfyTask:{prompt_id} has finished: {len(output_images)}')
    images_keys = sorted(output_images.keys(), reverse=True)
    imgs = [output_images[key] for key in images_keys]
    return imgs

def images_upload(images):
    result = {}
    if images is None:
        return result
    for k,np_image in images.items():
        pil_image = Image.fromarray(np_image)
        with BytesIO() as output:
            pil_image.save(output, format="PNG")
            output.seek(0)
            files = {'image': (f'image_{client_id}_{random.randint(1000, 9999)}.png', output)}
            data = {'overwrite': 'true', 'type': 'input'}
            response = httpx.post("http://{}/upload/image".format(server_address), files=files, data=data)
        result.update({k: response.json()["name"]})
    print(f'[ComfyClient] The ComfyTask:upload_input_images has finished: {len(result)}')
    return result


def process_flow(flow_name, params, images, callback=None):
    global ws

    flow_file = os.path.join(WORKFLOW_DIR, f'{flow_name}_api.json')
    if ws is None:
        ws = websocket.WebSocket()
        ws.connect("ws://{}/ws?clientId={}".format(server_address, client_id))
    images_map = images_upload(images)
    params.add_params(images_map)
    with open(flow_file, 'r', encoding="utf-8") as workflow_api_file:
        flowdata = json.load(workflow_api_file)
    print(f'[ComfyClient] Ready ComfyTask to process: workflow={flow_name}, params={params.params}')
    images = get_images(ws, params.convert2comfy(flowdata), callback=callback)

    return images

WORKFLOW_DIR = 'workflows'
COMFYUI_ENDPOINT = '127.0.0.1:8188'
server_address = COMFYUI_ENDPOINT
client_id = str(uuid.uuid4())  
ws = None
