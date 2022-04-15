import logging
import os
import threading
import time

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


class SnapTrigger(threading.Thread):

    def __init__(self, name, memsnaps):
        threading.Thread.__init__(self)
        self.memsnaps = memsnaps
        self.name = name
        self.done = False
        self.store_dir = cwd("storage", "analyses",
                             str(self.memsnaps.task.id),
                             "memsnaps")

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
            time.sleep(20)


class MemorySnaps(Auxiliary):
    def __init__(self):
        Auxiliary.__init__(self)
        self.thread = None

    def machine_running(self):
        try:
            status = self.guest_manager.get("/status", timeout=5).json()
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

    def start(self):

        try:
            self.thread = SnapTrigger("test", self)
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
            log.exception("Unable to stop the SnapTrigger thread: %s", e)
