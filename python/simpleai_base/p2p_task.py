import io
import time
import cbor2
import json
import threading
import queue
import numpy as np
from datetime import datetime
from PIL import Image
from api_params import convert_images
from simpleai_base.simpleai_base import gen_task_id


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

#本机发起任务
def request_p2p_task(task):
    global pending_tasks, token
    
    task_id = task.task_id
    task_method = task.method #'generate_image'
    if task_method=='generate_image':
        args = vars(task)["args"]
        args = convert_images(args, ndarray_to_webp_bytes)
        task.start_time = int(time.time() * 1000)
    else:
        args = task.args
    if task_method=='remote_ping':
        target_did = task.target_did
    else:
        target_did = None
    args_cbor2 = cbor2.dumps(args)
    logger.info(f"Sending {task_method} task to remote: {task_id}, length: {len(args_cbor2)}")
    if task_method=='remote_ping':  # sync task 
        return token.request_remote_task(task_id, task_method, args_cbor2, target_did, 'sync')

    pending_tasks[task_id] = (task, task_method, datetime.now())
    return token.request_remote_task(task_id, task_method, args_cbor2, target_did, 'async')

#任务结果回到本机后的回调， 异步任务的闭环，生命周期结束
def call_response_by_p2p_task(task_id, method, result_cbor2):
    global pending_tasks, worker

    response_length =len(result_cbor2)
    result = 'ok'
    if task_id in pending_tasks:
        task, task_method, start_time = pending_tasks[task_id]
        if method == 'remote_progress':
            percent, text, img = cbor2.loads(result_cbor2)
            if img is not None:
                img = webp_bytes_to_ndarray(img)
                logger.info(f"response({method}): task_id={task_id}, {percent}, {text}")
            worker.worker.progressbar(task, percent, text, img)
        elif method =='remote_result':
            imgs, progressbar_index, black_out_nsfw, censor, do_not_show_finished_images = cbor2.loads(result_cbor2)
            if imgs is not None:
                imgs = [webp_bytes_to_ndarray(img) for img in imgs]
                imgs_length = len(imgs)
            else:
                imgs_length = 0
            logger.info(f"response({method}), task_id={task_id}, images len={imgs_length}, response len={response_length}")
            delayed_task = AsyncTask(
                method="delayed_result",
                args=(task, imgs, progressbar_index, black_out_nsfw, censor, do_not_show_finished_images),
                task_id=f"{task_id}_delayed_result",
                delay=0.6,
            )
            async_task_queue.put(delayed_task)
        
        elif method =='remote_save_and_log':
            img, log_item = cbor2.loads(result_cbor2)
            logger.info(f"response({method}), task_id={task_id}, response len={response_length}")
            worker.worker.p2p_save_and_log(task, img, log_item)
        elif method =='remote_stop':
            processing_start_time, status = cbor2.loads(result_cbor2)
            processing_time1 = (int(time.time() * 1000) - processing_start_time)/1000.0
            processing_time2 = (int(time.time() * 1000) - task.start_time)/1000.0
            logger.info(f"response({method}): task_id={task_id}, Processing time (total): {processing_time1:.2f}/{processing_time2:.2f} seconds, {status}")
            delayed_task = AsyncTask(
                method="delayed_stop",
                args=(task, processing_start_time, status),
                task_id=f"{task_id}_delayed_stop",
                delay=2.0,
            )
            async_task_queue.put(delayed_task)
        elif method =='remote_minicpm':
            feedback = cbor2.loads(result_cbor2)
            logger.info(f'response({method}): task_id={task_id}, "{feedback}"')
            task.results.append(feedback)
            task.processing = False
            task.finished = True
            del pending_tasks[task_id]
        elif method =='remote_pong':
            feedback = cbor2.loads(result_cbor2)
            logger.info(f'response({method}): task_id={task_id}, "{feedback}"')
            task.results.append(feedback)
            task.processing = False
            task.finished = True
            del pending_tasks[task_id]
            
    return result



#接收远程任务，异步任务压入队列后即返回，同步任务直接返回结果
def call_request_by_p2p_task(task_id, method, args_cbor2):
    global worker

    from_node_sys = task_id.split('@')[1] if '@' in task_id else ''
    logger.info(f"Received remote task: {method}, {task_id}, length: {len(args_cbor2)}, from={from_node_sys}")
    result_async = 'no_response'
    if method == 'generate_image':
        args = cbor2.loads(args_cbor2)
        print(f"Received task args: type={type(args)}, args.len={len(args)}")
        args = convert_images(args, webp_bytes_to_ndarray)
        task = worker.AsyncTask(args=args, task_id=task_id)
        task.remote_task = from_node_sys
        with model_management.interrupt_processing_mutex:
            model_management.interrupt_processing = False
        worker.add_task(task)
        qsize = worker.get_task_size()
        logger.info(f"The {method} task was push to worker queue and qsize={qsize}")
        return result_async
    elif method == 'minicpm_inference':
        args = cbor2.loads(args_cbor2)
        task = AsyncTask(method=method, args=args, task_id=task_id, from_did=from_node_sys)
        async_task_queue.put(task)
        logger.info(f"The {method} task was push to async_task_queue")
        return result_async
    elif method =='remote_ping': #同步任务直接返回结果，不需要新建任务
        args = cbor2.loads(args_cbor2)
        logger.info(f"Pong {method} task: message={args}, from={from_node_sys}")
        return f'Pong: received {args} from {from_node_sys}.'
    elif method == 'service_info':
        args = cbor2.loads(args_cbor2)
        service_info = worker.worker.get_service_info(args)
        service_info_json = json.dumps(service_info)
        logger.info(f"service_info: {service_info}")
        return service_info_json


#远程任务处理完后回调发起节点
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


class AsyncTask:
    def __init__(self, method, args, task_id=None, from_did=None, target_did=None, delay=0):
        self.from_did = from_did
        self.target_did = target_did
        self.task_id = gen_task_id() if task_id is None else task_id
        self.method = method
        self.args = args
        self.results = []
        self.processing = False
        self.finished = False
        self.execute_time = time.time() + delay 

    def wait(self, timeout=None):
        if not self.finished:
            start_time = time.time()
            while not self.finished:
                if timeout is not None and time.time() - start_time > timeout:
                    raise TimeoutError(f'Task did not finish within the specified({timeout}s) timeout.')
                time.sleep(0.1)
        return self.results

class AsyncTaskWorker(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.running = True
        self.delayed_tasks = [] 

    def run(self):
        while self.running:
            try:
                task = async_task_queue.get(timeout=1)
                if task:
                    if hasattr(task, 'execute_time') and task.execute_time > time.time():
                        self.delayed_tasks.append(task)
                    else:
                        self.process_task(task)
            except queue.Empty:
                pass

            current_time = time.time()
            tasks_to_process = []
            remaining_tasks = []
                
            for task in self.delayed_tasks:
                if current_time >= task.execute_time:
                    tasks_to_process.append(task)
                else:
                    remaining_tasks.append(task)
            self.delayed_tasks = remaining_tasks
                
            for task in tasks_to_process:
                self.process_task(task)
               
            time.sleep(0.1)

    def process_task(self, task): #通用的远程任务处理，处理完后回调发起节点
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
            elif task.method == 'delayed_stop':
                original_task, processing_start_time, status = task.args
                task_id = original_task.task_id
                try:
                    worker.worker.stop_processing(original_task, processing_start_time, status)
                except Exception as e:
                    logger.error(f"Error in delayed stop_processing: {e}")
                finally:
                    if task_id in pending_tasks:
                        del pending_tasks[task_id]
            elif task.method == 'delayed_result':
                original_task, imgs, progressbar_index, black_out_nsfw, censor, do_not_show_finished_images = task.args
                task_id = original_task.task_id
                try:
                    worker.worker.yield_result(original_task, imgs, progressbar_index, black_out_nsfw, censor, do_not_show_finished_images)
                except Exception as e:
                    logger.error(f"Error in delayed yield_result: {e}")

            task.processing = False
            task.finished = True
        except Exception as e:
            logger.error(f"Error processing AsyncTask: {e}")
            task.processing = False

    def stop(self):
        self.running = False