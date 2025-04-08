import io
import time
import cbor2
import threading
import queue
import uuid
import numpy as np
from datetime import datetime
from PIL import Image


import logging
logger = logging.getLogger(__name__)

pending_tasks = {}
TASK_MAX_TIMEOUT = 1800

worker = None
model_management = None
token = None
minicpm = None

# Dedicated queue for AsyncTask
async_task_queue = queue.Queue()
async_task_thread = None

class AsyncTaskWorker(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.running = True

    def run(self):
        while self.running:
            try:
                task = async_task_queue.get(timeout=1)
                if task:
                    self.process_task(task)
            except queue.Empty:
                continue

    def process_task(self, task):
        try:
            task.processing = True
            if task.method == 'minicpm_inference':
                task.processing = True
                (image, prompt, max_tokens, temperature, top_p, top_k, repetition_penalty, seed) = task.args
                image = webp_bytes_to_ndarray(image)
                result = minicpm.inference_local(image, prompt, max_tokens, temperature, top_p, top_k, repetition_penalty, seed)
                task.results.append(result)
                
                task_id = task.task_id
                result_cbor2 = cbor2.dumps(result)
                task_method = 'remote_minicpm'
                token.response_remote_task(task_id, task_method, result_cbor2)

            task.processing = False
            task.finished = True
        except Exception as e:
            logger.error(f"Error processing AsyncTask: {e}")
            task.processing = False

    def stop(self):
        self.running = False


class AsyncTask:
    def __init__(self, method, args, task_id=None):
        self.task_id = str(uuid.uuid4()) if task_id is None else task_id
        self.method = method
        self.args = args
        self.results = []
        self.processing = False
        self.finished = False

    def wait(self, timeout=None):
        if not self.finished:
            start_time = time.time()
            while not self.finished:
                if timeout is not None and time.time() - start_time > timeout:
                    raise TimeoutError("Task did not finish within the specified({timeout}s) timeout.")
                time.sleep(0.1)
        return self.results


def init_p2p_task(_worker, _model_management, _token, _minicpm):
    global worker, model_management, token, minicpm, async_task_thread
    worker = _worker
    model_management = _model_management
    token = _token
    minicpm = _minicpm
    
    if async_task_thread is None:
        async_task_thread = AsyncTaskWorker()
        async_task_thread.start()


def gc_p2p_task():
    global pending_tasks, TASK_MAX_TIMEOUT
    for task_id in list(pending_tasks.keys()):
        task, task_method, start_time = pending_tasks[task_id]
        if (datetime.now() - start_time).total_seconds() > TASK_MAX_TIMEOUT:
            del pending_tasks[task_id]


def request_p2p_task(task):
    global pending_tasks, token
    
    task_id = task.task_id
    task_method = task.method #'generate_image'
    pending_tasks[task_id] = (task, task_method, datetime.now())
    logger.info(f"Remote {task_method} task was push to pending_tasks: {task_id}")
    if task_method=='generate_image':
        args = vars(task)["args"]
    else:
        args = task.args
    #print(f"Sending task args: type={type(args)}, value={args}")
    args_cbor2 = cbor2.dumps(args)
    logger.info(f"Sending task to remote: {task_id}, length: {len(args_cbor2)}")
    return token.request_remote_task(task_id, task_method, args_cbor2)



def call_request_by_p2p_task(task_id, method, args_cbor2):
    global worker

    if method == 'generate_image':
        logger.info(f"Received remote task: {method}, {task_id}, length: {len(args_cbor2)}")
        args = cbor2.loads(args_cbor2)
        #print(f"Received task args: type={type(args)}, value={args}")
    
        task = worker.AsyncTask(args=args, task_id=task_id)
        task.remote_task = True
        with model_management.interrupt_processing_mutex:
            model_management.interrupt_processing = False
        worker.add_task(task)
        qsize = worker.get_task_size()
        logger.info(f"The {method} task was push to worker queue and qsize={qsize}")
        return str(qsize)
    elif method == 'minicpm_inference':
        logger.info(f"Received remote task: {method}, {task_id}, length: {len(args_cbor2)}")
        args = cbor2.loads(args_cbor2)
        
        task = AsyncTask(method=method, args=args, task_id=task_id)
        async_task_queue.put(task)
        logger.info(f"The {method} task was push to async_task_queue")
        return "0"



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
    global pending_tasks, worker

    result = 'ok'
    if task_id in pending_tasks:
        task, task_method, start_time = pending_tasks[task_id]
        if method == 'remote_progress':
            percent, text, img = cbor2.loads(result_cbor2)
            if img is not None:
                img = webp_bytes_to_ndarray(img)
                logger.info(f"{method}: task_id={task_id}, {percent}, {text}")
            worker.worker.progressbar(task, percent, text, img)
        elif method =='remote_result':
            imgs, progressbar_index, black_out_nsfw, censor, do_not_show_finished_images = cbor2.loads(result_cbor2)
            if imgs is not None:
                imgs = [webp_bytes_to_ndarray(img) for img in imgs]
            worker.worker.yield_result(task, imgs, progressbar_index, black_out_nsfw, censor, do_not_show_finished_images)
            #print(f"response: method={method}, task_id={task_id}, image_num={len(imgs)}")
        elif method =='remote_save_and_log':
            img, log_item = cbor2.loads(result_cbor2)
            logger.info(f"{method}, task_id={task_id}")
            worker.worker.p2p_save_and_log(task, img, log_item)
        elif method =='remote_stop':
            processing_start_time, status = cbor2.loads(result_cbor2)
            logger.info(f"{method}: task_id={task_id}, {processing_start_time}, {status}")
            worker.worker.stop_processing(task, processing_start_time, status)
            del pending_tasks[task_id]
        elif method =='remote_minicpm':
            result = cbor2.loads(result_cbor2)
            logger.info(f"{method}: task_id={task_id}, {result}")
            task.results.append(result)
            task.processing = False
            task.finished = True
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
