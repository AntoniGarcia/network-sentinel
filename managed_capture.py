"""Adaptador de ciclo de vida para PyShark 0.6.

LiveCapture 0.6 deja abiertos los extremos padre de os.pipe(); se cierran
tras heredar los handles en dumpcap/TShark. Mantener este detalle aislado
facilita revisar el adaptador al actualizar PyShark.
"""
import asyncio
import os
import subprocess

from pyshark import LiveCapture
from pyshark.capture.capture import Capture
from pyshark.tshark.tshark import get_process_path


class ManagedLiveCapture(LiveCapture):
    async def _get_tshark_process(self, packet_count=None, stdin=None):
        read_fd, write_fd = os.pipe()
        try:
            params = [get_process_path(process_name='dumpcap', tshark_path=self.tshark_path)] + self._get_dumpcap_parameters()
            process = await asyncio.create_subprocess_exec(*params, stdout=write_fd, stderr=subprocess.PIPE)
            self._create_stderr_handling_task(process.stderr)
            self._created_new_process(params, process, process_name='Dumpcap')
            return await Capture._get_tshark_process(self, packet_count=packet_count, stdin=read_fd)
        finally:
            os.close(read_fd)
            os.close(write_fd)

    async def close_async(self):
        processes = list(self._running_processes)
        try:
            await super().close_async()
        finally:
            # asyncio.Process no ofrece close(); cerrar su transport evita
            # finalizadores pendientes al cerrar Proactor en Windows.
            for process in processes:
                transport = getattr(process, '_transport', None)
                if transport is not None:
                    transport.close()
            await asyncio.sleep(0)
