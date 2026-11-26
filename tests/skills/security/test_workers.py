import os
import signal
import subprocess
import sys
import unittest

from . import support


class TestScanWorkers(unittest.TestCase):
    def test_medusa_takes_95_percent_of_the_physical_cores_and_leaves_one_free(self):
        launch = support.launch()
        for cores, workers in ((1, 1), (2, 1), (4, 3), (14, 13), (20, 19), (40, 38), (100, 95)):
            with self.subTest(cores=cores):
                self.assertEqual(launch.scan_workers(cores), workers)

    def test_physical_cores_count_core_ids_per_socket_and_skip_hyperthreads(self):
        launch = support.launch()
        block = "processor\t: {n}\nphysical id\t: {socket}\ncore id\t\t: {core}\n\n"
        cpuinfo = "".join(block.format(n=n, socket=n // 4, core=n % 2) for n in range(8))
        self.assertEqual(launch.physical_cores(cpuinfo), 4)
        self.assertEqual(launch.physical_cores(""), os.cpu_count())

    def test_the_first_stop_signal_ignores_the_others_and_kills_the_group(self):
        launch = support.launch()
        for number in launch.STOPS:
            self.addCleanup(signal.signal, number, signal.signal(number, signal.default_int_handler))
        sleeper = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], start_new_session=True)
        self.addCleanup(support.ended, [sleeper.pid])
        launch.halt([sleeper.pid], launch.STOPS)
        self.assertEqual([signal.getsignal(number) for number in launch.STOPS], [signal.SIG_IGN] * len(launch.STOPS))
        self.assertEqual(sleeper.wait(timeout=10), -signal.SIGKILL)
