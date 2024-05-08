import asyncio

from .simpleai import get_ipaddr_from_public, get_port_availability, get_ipaddr_from_stream

public_ip = None
port = None
async def async_task():
    global public_ip, port
    task_public_ip = asyncio.create_task(get_ipaddr_from_public(False))
    task_port = asyncio.create_task(get_port_availability(get_ipaddr_from_stream(), 8186))
    public_ip = await task_public_ip
    port = await task_port


asyncio.run(async_task())