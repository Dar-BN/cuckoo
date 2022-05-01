import logging
import os
import subprocess
import threading
import time
import tempfile

from pprint import pformat

from cuckoo.common.abstracts import Auxiliary
from cuckoo.common.constants import CUCKOO_GUEST_PORT, faq
from cuckoo.common.exceptions import CuckooOperationalError, \
    CuckooGuestError, CuckooGuestCriticalTimeout
from cuckoo.misc import cwd, getuser, Popen
from cuckoo.core.scheduler import get_machinery

log = logging.getLogger(__name__)


def my_dir(obj):
    if obj is not None:
        return pformat(dir(obj))
    else:
        return "<None>"


class BackgroundPopen(subprocess.Popen):
    @staticmethod
    def prefix_handler(log_fn, prefix):
        return lambda line: log_fn("%s%s", prefix, line)

    @staticmethod
    def _proxy_lines(pipe, handler):
        with pipe:
            for line in pipe:
                handler(line)

    def __init__(self, out_handler, err_handler, *args, **kwargs):
        kwargs['stdout'] = subprocess.PIPE
        kwargs['stderr'] = subprocess.PIPE
        super(self.__class__, self).__init__(*args, **kwargs)
        threading.Thread(target=self._proxy_lines,
                         args=[self.stdout, out_handler]).start()
        threading.Thread(target=self._proxy_lines,
                         args=[self.stderr, err_handler]).start()


class SnapTrigger(threading.Thread):

    def __init__(self, name, memsnaps):
        threading.Thread.__init__(self)
        self.memsnaps = memsnaps
        self.name = name
        self.done = False
        self.store_dir = cwd("storage", "analyses",
                             str(self.memsnaps.task.id),
                             "memsnaps")
        self.freq = memsnaps.frequency

    @property
    def storage_dir(self):
        if not os.path.exists(self.store_dir):
            os.mkdir(self.store_dir)

        return self.store_dir

    @property
    def snap_name(self):
        return os.path.join(
            self.storage_dir,
            "%s-%d.dmp" % (self.name, int(time.time() * 1000))
        )

    def run(self):
        while not self.done:
            try:
                log.info("SnapTrigger: %s (state=%s; dir=%s)", self.name,
                         self.memsnaps.machine_running(),
                         cwd("storage", "analyses",
                             str(self.memsnaps.task.id)))
                log.info("task = %s", my_dir(self.memsnaps.task))
                log.info("machine = %s",
                         my_dir(self.memsnaps.machine))
                log.info("guest_manager = %s",
                         my_dir(self.memsnaps.guest_manager))
                log.info("options = %s",
                         my_dir(self.memsnaps.options))
                if get_machinery():
                    log.info("machinery = %s", my_dir(get_machinery()))
                    get_machinery().dump_memory(self.memsnaps.machine.label,
                                                self.snap_name)
            except Exception as ex:
                log.error("Exception: %s", ex)
                log.exception(ex)
            time.sleep(self.freq)


class RamSnapTrigger(threading.Thread):

    def __init__(self, memsnaps):
        threading.Thread.__init__(self)
        self.memsnaps = memsnaps
        self.done = False
        self.capture_proc = None
        self.socket_path = tempfile.mktemp(prefix='.mig', suffix='.sock')
        self.store_dir = cwd("storage", "analyses",
                             str(self.memsnaps.task.id),
                             "ramsnaps")

    @property
    def storage_dir(self):
        if not os.path.exists(self.store_dir):
            os.mkdir(self.store_dir)

        return self.store_dir

    def run(self):

        started_migration = False

        while not self.done:
            try:
                time.sleep(3)

                log.info("RamSnapTrigger: state=%s; dir=%s",
                         self.memsnaps.machine_running(),
                         self.storage_dir)

                if not self.memsnaps.machine_running():
                    log.debug("RamSnapTrigger: machine not running...")
                    continue

                # Start migration capture process
                if self.capture_proc is None:
                    cmd = ["/usr/bin/qemu-capture-migration"]
                    # if logging.getLogger().level <= logging.DEBUG:
                    #     cmd.append("-D")
                    cmd.extend(["-s", self.socket_path])
                    cmd.extend(["-o", self.store_dir])

                    log.info("Running: %s", " ".join(cmd))
                    self.capture_proc = BackgroundPopen(
                        BackgroundPopen.prefix_handler(log.debug,
                                                       "(stdout) capture: "),
                        BackgroundPopen.prefix_handler(log.debug,
                                                       "(stderr) capture: "),
                        cmd, close_fds=True)

                # Ask Qemu to start sending data
                if not started_migration and self.memsnaps.machinery:
                    if os.path.exists(self.socket_path):
                        # log.info("machinery = %s",
                        #          my_dir(self.memsnaps.machinery))
                        log.info("Starting migraiton for %s, on socket %s",
                                 self.memsnaps.machine.label, self.socket_path)

                        self.memsnaps.machinery.start_migration(
                            self.memsnaps.machine.label,
                            "unix:" + self.socket_path)
                        started_migration = True
                    else:
                        log.info("Migration socket doesn't exist yet: %s",
                                 self.socket_path)
            except Exception as ex:
                log.error("Exception: %s", ex)
                log.exception(ex)

        if self.capture_proc is not None:
            self.capture_proc.kill()
            self.capture_proc.wait()
            self.capture_proc = None


class MemorySnaps(Auxiliary):
    def __init__(self):
        Auxiliary.__init__(self)
        self.thread = None
        self._machinery = get_machinery()
        self._output_dir = None

    @property
    def machinery(self):
        if self._machinery is None:
            self._machinery = get_machinery()

        return self._machinery

    def machine_running(self):
        try:
            status = self.machinery._status(self.machine.label)
            log.info("Machine %s QMP status: %s", self.machine.label, status)
            if status != self.machinery.RUNNING:
                return False
        except Exception as e:
            log.error("Virtual machine QMP status failed. %s", e)
            return False

        try:
            status = self.guest_manager.get("/status", timeout=5).json()
            # status = self.guest_manager._status(self.machine.label)
            log.info("Got status: %s", pformat(status))
        except CuckooGuestError:
            # this might fail due to timeouts or just temporary network
            # issues thus we don't want to abort the analysis just yet and
            # wait for things to recover
            log.warning(
                "Virtual Machine /status failed. This can indicate the "
                "guest losing network connectivity"
            )
            return False
        except Exception as e:
            log.error("Virtual machine /status failed. %s", e)
            return False

        if status["status"] == "complete":
            log.info("%s: analysis completed successfully", self.vmid)
            return False
        elif status["status"] == "exception":
            log.warning(
                "%s: analysis #%s caught an exception\n%s",
                self.vmid, self.task_id, status["description"]
            )
            return False

        log.info("Got status: %s", pformat(status))
        return True

    @property
    def is_ramsnap(self):
        _rv = self.task and self.task.options and \
            self.task.options.get("ramsnap", 'no') == 'yes'
        log.debug("is_ramsnap: %s", _rv)

        return _rv

    @property
    def frequency(self):
        _rv = 20

        try:
            val = "<not specified>"
            if self.task and self.task.options:
                val = self.task.options.get("frequency", 20)
                _rv = int(val)
                _rv = max(1, min(60, _rv))
        except ValueError as ex:
            log.error("Error processing frequency value: %s (%s)",
                      val, ex)

        log.debug("frequency: %d", _rv)
        return _rv

    def start(self):

        try:
            log.debug("DPK: %s",
                      str(self.task.options) if self.task else 'None')
            if self.is_ramsnap:
                self.thread = RamSnapTrigger(self)
            else:
                self.thread = SnapTrigger("periodic-dump", self)

            self._output_dir = self.thread.store_dir
            self.thread.start()

        except (OSError, ValueError):
            log.exception(
                "Failed to start MemorySnaps (task=%s)",
                self.task.id
            )
            return False

        log.info(
            "Starting MemorySnaps"
        )
        return True

    def stop(self):
        """Stop capturing memory snaps
        @return: operation status.
        """

        log.info("Stopping MemorySnap")

        # The tcpdump process was never started in the first place.
        if not self.thread:
            return

        try:
            self.thread.done = True
            self.thread.join()
        except Exception as e:
            log.exception("Unable to stop the RamSnapTrigger thread: %s", e)

        if self.is_ramsnap:
            memsnaps_dir = cwd("storage", "analyses",
                            str(self.task.id),
                            "memsnaps")
            # Now need to generate dump that volatility can read
            cmd = ["/usr/bin/qemu-process-ramsnaps"]
            # if logging.getLogger().level <= logging.DEBUG:
            #     cmd.append("-D")

            cmd.extend(["-i", os.path.join(self._output_dir, "pc-ram.idx")])
            cmd.extend(["-p", os.path.join(memsnaps_dir, "memory-dump")])
            # cmd.extend(["-g", "3"])
            cmd.extend(["-m", "30"])

            log.info("Running: %s", " ".join(cmd))

            dump_gen_proc = BackgroundPopen(
                BackgroundPopen.prefix_handler(log.debug,
                                                "(stdout) dump-gen: "),
                BackgroundPopen.prefix_handler(log.debug,
                                                "(stderr) dump-gen: "),
                cmd, close_fds=True)

            dump_gen_proc.wait()
