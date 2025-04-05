import time
import cbor2
from datetime import datetime
import numpy as np
from PIL import Image
import io

pending_tasks = {}
TASK_MAX_TIMEOUT = 1800

worker = None
model_management = None
token = None
callback_result = None
callback_progress = None
callback_stop = None   
callback_save_and_log = None

def init_p2p_task(_worker, _model_management, _token):
    global worker, model_management, token, callback_result, callback_progress, callback_save_and_log, callback_stop
    worker = _worker
    model_management = _model_management
    token = _token
    callback_result = _worker.worker.yield_result
    callback_progress = _worker.worker.progressbar
    callback_save_and_log = _worker.worker.p2p_save_and_log
    callback_stop = _worker.worker.stop_processing

def gc_p2p_task():
    global pending_tasks, TASK_MAX_TIMEOUT
    for task_id in list(pending_tasks.keys()):
        task, task_method, start_time = pending_tasks[task_id]
        if (datetime.now() - start_time).total_seconds() > TASK_MAX_TIMEOUT:
            del pending_tasks[task_id]


def request_p2p_task(task):
    global pending_tasks, token
    
    task_id = task.task_id
    task_method = 'generate_image'
    pending_tasks[task_id] = (task, task_method, datetime.now())
    print(f"generate_image task was push to pending_tasks: {pending_tasks[task_id]}")
    args = vars(task)["args"]
    #print(f"Sending task args: type={type(args)}, value={args}")
    args_cbor2 = cbor2.dumps(args)
    print(f"Sending task: {task_id}, args_cbor2 type: {type(args_cbor2)}, length: {len(args_cbor2)}")
    return token.request_remote_task(task_id, task_method, args_cbor2)



def call_request_by_p2p_task(task_id, method, args_cbor2):
    global worker

    if method != 'generate_image':
        return
    print(f"Received task: {task_id}, args_cbor2 type: {type(args_cbor2)}, length: {len(args_cbor2)}")
    args = cbor2.loads(args_cbor2)
    print(f"Received task args: type={type(args)}, value={args}")
    
    task = worker.AsyncTask(args=args, task_id=task_id)
    task.remote_task = True
    
    with model_management.interrupt_processing_mutex:
        model_management.interrupt_processing = False

    worker.add_task(task)
    qsize = worker.get_task_size()
    print(f"generate_image task was push to worker queue and qsize={qsize}")
    return str(qsize)


def call_remote_progress(task, number, text, img=None):
    task_id = task.task_id
    if img is not None:
        img = ndarray_to_webp_bytes(img)
    result = (number, text, img)
    result_cbor2 = cbor2.dumps(result)
    task_method = 'remote_progress'
    return token.response_remote_task(task_id, task_method, result_cbor2)

def call_remote_result(task, imgs, progressbar_index, black_out_nsfw, censor=True, do_not_show_finished_images=False):
    task_id = task.task_id
    if imgs is not None:
        imgs = [ndarray_to_webp_bytes(img) for img in imgs]
    result = (imgs, progressbar_index, black_out_nsfw, censor, do_not_show_finished_images)
    result_cbor2 = cbor2.dumps(result)
    task_method = 'remote_result'
    return token.response_remote_task(task_id, task_method, result_cbor2)

def call_remote_save_and_log(task, img, log_item):
    task_id = task.task_id
    result = (img, log_item)
    result_cbor2 = cbor2.dumps(result)
    task_method = 'remote_save_and_log'
    return token.response_remote_task(task_id, task_method, result_cbor2)

def call_remote_stop(task, processing_start_time, status='Finished'):
    task_id = task.task_id
    result = (processing_start_time, status)
    result_cbor2 = cbor2.dumps(result)
    task_method = 'remote_stop'
    return token.response_remote_task(task_id, task_method, result_cbor2)

def call_response_by_p2p_task(task_id, method, result_cbor2):
    global pending_tasks, callback_result, callback_progress, callback_stop, callback_save_and_log

    result = 'ok'
    if task_id in pending_tasks:
        task, task_method, start_time = pending_tasks[task_id]
        print(f"call_response: method={method}, task_id={task_id}")
        if method == 'remote_progress':
            percent, text, img = cbor2.loads(result_cbor2)
            if img is not None:
                img = webp_bytes_to_ndarray(img)
            callback_progress(task, percent, text, img)
        elif method =='remote_result':
            imgs, progressbar_index, black_out_nsfw, censor, do_not_show_finished_images = cbor2.loads(result_cbor2)
            if imgs is not None:
                imgs = [webp_bytes_to_ndarray(img) for img in imgs]
            callback_result(task, imgs, progressbar_index, black_out_nsfw, censor, do_not_show_finished_images)
        elif method =='remote_save_and_log':
            img, log_item = cbor2.loads(result_cbor2)
            callback_save_and_log(task, img, log_item)
        elif method =='remote_stop':
            processing_start_time, status = cbor2.loads(result_cbor2)
            callback_stop(task, processing_start_time, status)
            del pending_tasks[task_id]
    return result


def ndarray_to_webp_bytes(image: np.ndarray, lossless: bool = False) -> bytes:
    if not isinstance(image, np.ndarray):
        raise TypeError("Input must be a numpy.ndarray.")
    if image.dtype != np.uint8:
        raise ValueError("Image data type must be uint8.")

    pil_image = Image.fromarray(image)
    buffer = io.BytesIO()
    pil_image.save(buffer, format="WEBP", quality=95, lossless=lossless)
    return buffer.getvalue()

def webp_bytes_to_ndarray(webp_bytes: bytes) -> np.ndarray:
    if not isinstance(webp_bytes, bytes):
        raise TypeError("Input must be bytes.")
    return np.array(Image.open(io.BytesIO(webp_bytes)))  
