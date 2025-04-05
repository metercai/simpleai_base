import time
import cbor2
from datetime import datetime

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
        task, start_time = pending_tasks[task_id]
        if (datetime.now() - start_time).total_seconds() > TASK_MAX_TIMEOUT:
            del pending_tasks[task_id]


def request_p2p_task(task):
    global pending_tasks, token
    
    task_id = task.task_id
    pending_tasks[task_id] = (task, datetime.now())
    task_method = 'generate_image'
    args = vars(task)["args"]
    print(f"Sending task args: type={type(args)}, value={args}")
    args_cbor2 = cbor2.dumps(args)
    print(f"Sending task: {task_id}, args_cbor2 type: {type(args_cbor2)}, length: {len(args_cbor2)}")
    print(f"Sending args_cbor2 hex: {args_cbor2.hex()}")
    return token.request_remote_task(task_id, task_method, args_cbor2)



def call_request_by_p2p_task(task_id, method, args_cbor2):
    global worker

    if method != 'generate_image':
        return
    print(f"Received task: {task_id}, args_cbor2 type: {type(args_cbor2)}, length: {len(args_cbor2)}")
    print(f"Received args_cbor2 hex: {args_cbor2.hex()}")
    args = cbor2.loads(args_cbor2)
    print(f"Received task args: type={type(args)}, value={args}")
    
    task = worker.AsyncTask(args=args, task_id=task_id)
    task.remote_task = True
    print(f"Received remote task: {task.task_id}, method: {method}, args: {args}")

    with model_management.interrupt_processing_mutex:
        model_management.interrupt_processing = False

    MAX_WAIT_TIME = 480
    POLL_INTERVAL = 0.1

    worker.add_task(task)
    MAX_LOOP_NUM = worker.get_task_size()
    print(f"task was pushed: qsize={MAX_LOOP_NUM}")
    
    last_update_time = time.time()
    loop_num = 0
    ready_flag = False
    while True:
        current_time = time.time()
        if (current_time - MAX_WAIT_TIME*loop_num - last_update_time) < MAX_WAIT_TIME:
            qsize = worker.get_task_size()
            call_remote_progress(task, 1, f'远程生图任务排队中({qsize})，请等待...')
            if worker.get_processing_id() == task.task_id:
                ready_flag = True
                break
        else:
            loop_num += 1
            if loop_num > MAX_LOOP_NUM:
                print(f'ready to restart worker thread...')
                worker.restart(task)
                break
        time.sleep(POLL_INTERVAL)

    execution_start_time = time.perf_counter()
    finished = False
    MAX_WAIT_TIME = 480
    POLL_INTERVAL = 0.08

    last_update_time = time.time()
    while not finished:
        current_time = time.time()
        if current_time - last_update_time > MAX_WAIT_TIME or not ready_flag:
            call_remote_progress(task, 0, '生图任务已超时!')
            print(f"Generate task timeout after {MAX_WAIT_TIME} seconds")
            task.last_stop = 'stop'
            if (task.processing):
                print("Send interrupt flag to process and comfyd")
                worker.interrupt_processing()
            break
        time.sleep(POLL_INTERVAL)
        finished = not task.processing


def call_remote_progress(task, number, text, img=None):
    task_id = task.task_id
    result = (number, text, img)
    result_cbor2 = cbor2.dumps(result)
    task_method = 'remote_progress'
    return token.response_remote_task(task_id, task_method, result_cbor2)

def call_remote_result(task, imgs, progressbar_index, black_out_nsfw, censor=True, do_not_show_finished_images=False):
    task_id = task.task_id
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

    if task_id in pending_tasks:
        task, start_time = pending_tasks[task_id]
        if method == 'remote_progress':
            percent, text, img = cbor2.loads(result_cbor2)
            callback_progress(task, percent, text, img)
        elif method =='remote_result':
            imgs, progressbar_index, black_out_nsfw, censor, do_not_show_finished_images = cbor2.loads(result_cbor2)
            callback_result(task, imgs, progressbar_index, black_out_nsfw, censor, do_not_show_finished_images)
        elif method =='remote_save_and_log':
            img, log_item = cbor2.loads(result_cbor2)
            callback_save_and_log(task, img, log_item)
        elif method =='remote_stop':
            processing_start_time, status = cbor2.loads(result_cbor2)
            callback_stop(task, processing_start_time, status)
            del pending_tasks[task_id]

