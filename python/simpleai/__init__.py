import asyncio

from simpleai import simpleai


async def async_task():
    global public_ip, port
    public_ip = await simpleai.get_ipaddr_from_public(False)
    port = await simpleai.get_port_availability(simpleai.get_ipaddr_from_stream(), 8186)


#asyncio.run(async_task())
