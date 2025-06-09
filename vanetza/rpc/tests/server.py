import asyncio
import capnp
import math
import os
import time

capnp.remove_import_hook()
vanetza_capnp = capnp.load('vanetza.capnp', 'Vanteza RPC', ['/usr/include/', '/usr/local/include/'])

class PeriodicTask:
    def __init__(self, timeout):
        self._timeout = timeout
        self._task = asyncio.create_task(self._do_loop())

    async def _do_loop(self):
        while asyncio.get_running_loop().is_running():
            await asyncio.sleep(self._timeout)
            await self.action()

    def cancel(self):
        self._task.cancel()

    async def action(self):
        pass


class PeriodicCbrGenerator(PeriodicTask):
    def __init__(self, callback):
        super().__init__(timeout=0.1)
        self._callback = callback

    async def action(self):
        if callable(self._callback):
            await self._callback(0.3 + 0.25 * math.sin(0.2*math.pi*time.monotonic()))


class PeriodicDataGenerator(PeriodicTask):
    def __init__(self, callback):
        super().__init__(timeout=2.5)
        self._callback = callback

    async def action(self):
        if callable(self._callback):
            await self._callback()


class Server(vanetza_capnp.LinkLayer.Server):
    def __init__(self):
        self._cbr = PeriodicCbrGenerator(self._notify_cbr)
        self._data = PeriodicDataGenerator(self._notify_data)

    def stop(self):
        self._cbr.cancel()
        self._data.cancel()

    async def _notify_cbr(self, channel_load: float):
        if self._cbr_listener:
            cbr = {
                'busy': int(channel_load * 1000),
                'samples': 1000
            }
            await self._cbr_listener.onCbrReport(cbr=cbr)

    async def _notify_data(self):
        if self._data_listener:
            frame = {
                'sourceAddress': b"\xde\xad\xc0\xff\xff\xee",
                'destinationAddress': b"\xff\xff\xff\xff\xff\xff",
                'payload': b"Vanetza"
            }
            rx = {
                'wlan': { 'power': -60 * 8, 'datarate': 6 * 2 }
            }
            await self._data_listener.onDataIndication(frame=frame, rxParams=rx)


    async def identify(self, **kwargs):
        return (os.getpid(), 1)

    async def transmitData(self, frame, txParams, **kwargs):
        print("client requested data transmission")
        return vanetza_capnp.LinkLayer.ErrorCode.ok

    async def subscribeData(self, listener, **kwargs):
        print("client subscribed data indications")
        self._data_listener = listener

    async def subscribeCbr(self, listener, **kwargs):
        print("client subscribed CBR reports")
        self._cbr_listener = listener

    async def setSourceAddress(self, address, **kwargs):
        print(f"client set source address: {address}")
        if (len(address) != 6):
            return vanetza_capnp.LinkLayer.ErrorCode.invalidArgument
        else:
            return vanetza_capnp.LinkLayer.ErrorCode.ok

async def new_connection(stream):
    server = Server()
    await capnp.TwoPartyServer(stream, bootstrap=server).on_disconnect()
    server.stop()

async def main():
    server = await capnp.AsyncIoStream.create_server(new_connection, '*', '23057')
    async with server:
        await server.serve_forever()

if __name__ == '__main__':
    asyncio.run(capnp.run(main()))
