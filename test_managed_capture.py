"""Comprueba que el adaptador cierre ambos descriptores también si falla TShark."""
import asyncio
import os
import unittest
from unittest.mock import AsyncMock, patch

from managed_capture import ManagedLiveCapture


class ManagedCaptureTests(unittest.IsolatedAsyncioTestCase):
    async def test_parent_pipe_descriptors_close_on_start_failure(self):
        instance = ManagedLiveCapture.__new__(ManagedLiveCapture)
        instance.tshark_path = 'tshark'
        instance._running_processes = set()
        instance._stderr_handling_tasks = []
        read_fd, write_fd = os.pipe()
        process = type('Process', (), {'stderr':None})()
        with patch('managed_capture.os.pipe',return_value=(read_fd,write_fd)), patch('managed_capture.get_process_path',return_value='dumpcap'), patch.object(instance,'_get_dumpcap_parameters',return_value=[]), patch.object(instance,'_create_stderr_handling_task'), patch.object(instance,'_created_new_process'), patch('managed_capture.asyncio.create_subprocess_exec',new=AsyncMock(return_value=process)), patch('managed_capture.Capture._get_tshark_process',new=AsyncMock(side_effect=RuntimeError('startup failed'))):
            with self.assertRaises(RuntimeError):
                await instance._get_tshark_process()
        for descriptor in (read_fd, write_fd):
            with self.assertRaises(OSError):
                os.fstat(descriptor)


if __name__ == '__main__':
    unittest.main()
