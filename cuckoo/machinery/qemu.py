# Copyright (C) 2015-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json
import os
import time
import logging
import subprocess
import os.path

from threading import RLock

from cuckoo.common.abstracts import Machinery
from cuckoo.common.ipc import IPCError, UnixSockClient, timeout_read_response
from cuckoo.common.config import config
from cuckoo.common.exceptions import CuckooCriticalError
from cuckoo.common.exceptions import CuckooMachineError

log = logging.getLogger(__name__)

# this whole semi-hardcoded commandline thing is not the best
#  but in the config files we can't do arrays etc so we'd have to parse the
#  configured commandlines somehow and then fill in some more things
#  anyways, if someone has a cleaner suggestion for this, let me know
#  -> for now, just modify this to your needs
QEMU_ARGS = {
    "default": {
        "cmdline": ["qemu-system-x86_64", "-display", "none"],
        "params": {
            "memory": "512M",
            "mac": "52:54:00:12:34:56",
            "kernel": "{imagepath}/vmlinuz",
        },
    },
    "mipsel": {
        "cmdline": [
            "qemu-system-mipsel", "-display", "none", "-M", "malta", "-m", "{memory}",
            "-kernel", "{kernel}",
            "-hda", "{snapshot_path}",
            "-append", "root=/dev/sda1 console=tty0",
            "-netdev", "tap,id=net_{vmname},ifname=tap_{vmname},script=no,downscript=no",
            "-device", "e1000,netdev=net_{vmname},mac={mac}",  # virtio-net-pci doesn't work here
        ],
        "params": {
            "kernel": "{imagepath}/vmlinux-3.2.0-4-4kc-malta-mipsel",
        }
    },
    "mips": {
        "cmdline": [
            "qemu-system-mips", "-display", "none", "-M", "malta", "-m", "{memory}",
            "-kernel", "{kernel}",
            "-hda", "{snapshot_path}",
            "-append", "root=/dev/sda1 console=tty0",
            "-netdev", "tap,id=net_{vmname},ifname=tap_{vmname},script=no,downscript=no",
            "-device", "e1000,netdev=net_{vmname},mac={mac}",  # virtio-net-pci doesn't work here
        ],
        "params": {
            "kernel": "{imagepath}/vmlinux-3.2.0-4-4kc-malta-mips",
        }
    },
    "armwrt": {
        "cmdline": [
            "qemu-system-arm", "-display", "none", "-M", "realview-eb-mpcore", "-m", "{memory}",
            "-kernel", "{kernel}",
            "-drive", "if=sd,cache=unsafe,file={snapshot_path}",
            "-append", "console=ttyAMA0 root=/dev/mmcblk0 rootwait",
            "-net", "tap,ifname=tap_{vmname},script=no,downscript=no", "-net", "nic,macaddr={mac}",  # this by default needs /etc/qemu-ifup to add the tap to the bridge, slightly awkward
        ],
        "params": {
            "kernel": "{imagepath}/openwrt-realview-vmlinux.elf",
        }
    },
    "arm": {
        "cmdline": [
            "qemu-system-arm", "-display", "none", "-M", "versatilepb", "-m", "{memory}",
            "-kernel", "{kernel}", "-initrd", "{initrd}",
            "-hda", "{snapshot_path}",
            "-append", "root=/dev/sda1",
            "-net", "tap,ifname=tap_{vmname},script=no,downscript=no", "-net", "nic,macaddr={mac}",  # this by default needs /etc/qemu-ifup to add the tap to the bridge, slightly awkward
        ],
        "params": {
            "memory": "256M",  # 512 didn't work for some reason
            "kernel": "{imagepath}/vmlinuz-3.2.0-4-versatile-arm",
            "initrd": "{imagepath}/initrd-3.2.0-4-versatile-arm",
        }
    },
    "x64": {
        "cmdline": [
            "qemu-system-x86_64", "-display", "none", "-m", "{memory}",
            "-hda", "{snapshot_path}",
            # "-net", "tap,ifname=tap_{vmname},script=no,downscript=no", "-net", "nic,macaddr={mac}",  # this by default needs /etc/qemu-ifup to add the tap to the bridge, slightly awkward
            "-qmp", "unix:{qmp_socket_path},server,nowait",
            "-monitor", "none",
            "-netdev", "tap,id=net0,ifname=tap_{vmname},script=no,downscript=no", "-device", "rtl8139,netdev=net0,mac={mac}",  # this by default needs /etc/qemu-ifup to add the tap to the bridge, slightly awkward
        ],
        "params": {
            "memory": "1024M",
        }
    },
    "x86": {
        "cmdline": [
            "qemu-system-i386", "-display", "none", "-m", "{memory}",
            "-hda", "{snapshot_path}",
            "-net", "tap,ifname=tap_{vmname},script=no,downscript=no", "-net", "nic,macaddr={mac}",  # this by default needs /etc/qemu-ifup to add the tap to the bridge, slightly awkward
        ],
        "params": {
            "memory": "1024M",
        }
    },
}


class QMPError(Exception):
    pass


# A QMP Client class, copied from cuckoo3
class QMPClient(object):
    """A simple QEMU Machine Protocol client to send commands and request
    states."""

    def __init__(self, qmp_sockpath):
        self._sockpath = qmp_sockpath

        self._client_obj = None
        # Lock should be kept when writing and reading. This prevents
        # another thread (y) from sending a command while another (x) is
        # reading. This would cause the message for thread y to be ignored/lost
        # when x is reading.
        self._lock = RLock()

    @property
    def _client(self):
        with self._lock:
            if not self._client_obj:
                self.connect()

            return self._client_obj

    def execute(self, command, args_dict=None):
        with self._lock:
            try:
                self._client.send_json_message({
                    "execute": command,
                    "arguments": args_dict or {}
                })
            except IPCError as e:
                raise QMPError(
                    f"Failed to send command to QMP socket. "
                    f"Command: {command}, args: {args_dict}. {e}"
                )

    def read(self, timeout=60):
        with self._lock:
            try:
                return timeout_read_response(self._client, timeout=timeout)
            except IPCError as e:
                raise QMPError(
                    f"Failed to read response from QMP socket. {e}"
                )

    def wait_read_return(self, timeout=60):
        with self._lock:
            start = time.monotonic()
            while True:
                mes = self.read(timeout=timeout)
                # Skip all messages that do not have the return key.
                ret = mes.get("return")
                if ret:
                    return ret

                if time.monotonic() - start >= timeout:
                    raise QMPError("Timeout waiting for return")

    def query_status(self):
        with self._lock:
            self.execute("query-status")
            return self.wait_read_return()["status"]

    def connect(self):
        # Connect and perform 'capabilities handshake'. Must be performed
        # before any commands can be sent.
        with self._lock:
            self._client_obj = UnixSockClient(self._sockpath)
            self._client_obj.connect(maxtries=1, timeout=20)
            try:
                res = timeout_read_response(self._client_obj, timeout=60)
            except IPCError as e:
                raise QMPError(
                    f"Failure while waiting for QMP connection header. {e}"
                )

            if not res.get("QMP"):
                raise QMPError(
                    f"Unexpected QMP connection header. Header: {res}"
                )

            self.execute("qmp_capabilities")

    def close(self):
        self._client.cleanup()


class QEMU(Machinery):
    """Virtualization layer for QEMU (non-KVM)."""

    # VM states.
    RUNNING = "running"
    STOPPED = "stopped"
    ERROR = "machete"

    def __init__(self):
        super(QEMU, self).__init__()
        self.state = {}
        self.qmp_socket_paths = None

    def _initialize_check(self):
        """Run all checks when a machine manager is initialized.
        @raise CuckooMachineError: if QEMU binary is not found.
        """
        # VirtualBox specific checks.
        if not self.options.qemu.path:
            raise CuckooCriticalError("QEMU binary path missing, "
                                      "please add it to the config file")
        if not os.path.exists(self.options.qemu.path):
            raise CuckooCriticalError("QEMU binary not found at "
                                      "specified path \"%s\"" %
                                      self.options.qemu.path)

        self.qemu_dir = os.path.dirname(self.options.qemu.path)
        self.qemu_img = os.path.join(self.qemu_dir, "qemu-img")

    def start(self, label, task):
        """Start a virtual machine.
        @param label: virtual machine label.
        @param task: task object.
        @raise CuckooMachineError: if unable to start.
        """
        log.debug("Starting vm %s" % label)

        vm_info = self.db.view_machine_by_label(label)
        vm_options = getattr(self.options, vm_info.name)

        if vm_options.snapshot:
            snapshot_path = vm_options.image
        else:
            snapshot_path = os.path.join(
                os.path.dirname(vm_options.image),
                "snapshot_%s.qcow2" % vm_info.name
            )
            if os.path.exists(snapshot_path):
                os.remove(snapshot_path)

            # make sure we use a new harddisk layer by creating a new
            # qcow2 with backing file
            try:
                proc = subprocess.Popen([
                    self.qemu_img, "create", "-f", "qcow2", "-F", "qcow2",
                    "-b", vm_options.image, snapshot_path
                ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                output, err = proc.communicate()
                if err:
                    raise OSError(err)
            except OSError as e:
                raise CuckooMachineError(
                    "QEMU failed starting the machine: %s" % e
                )

        qmp_socket_path = "/tmp/qmp-sock-%s-%s.sock" % \
            (label, vm_info.name)

        mi = os.path.join(os.path.dirname(vm_options.image),
                          "machineinfo.json")
        cmdline = []
        if os.path.exists(mi):
            try:
                mi_dict = dict()
                with open(mi, 'r') as fp:
                    mi_dict = json.load(fp)
                machine = mi_dict.get("machine", None)
                if machine is not None:
                    start_args = machine.get("start_args", None)
                    if start_args is not None:
                        new_start_args = []
                        skip_one = False
                        for arg in start_args:
                            if skip_one:
                                skip_one = False
                                continue

                            # Replace %DISPOSABLE_DISK_PATH% with
                            # {snapshot_path}
                            arg = arg.replace("%DISPOSABLE_DISK_PATH%",
                                              "{snapshot_path}")

                            # Replace netdev with tap config
                            if arg == "-netdev":
                                new_start_args.extend([
                                    "-netdev",
                                     "tap,id=net_{vmname},ifname=tap_{vmname},script=no,downscript=no"])
                                skip_one = True
                                continue

                            # Skip audio (seems to hang VM)
                            if arg == "-soundhw":
                                skip_one = True
                                continue

                            # Change device netdev to "netdev=net_{vmname},mac={mac}"
                            if "netdev=" in arg:
                                fields = arg.split(',')
                                new_arg = []
                                for field in fields:
                                    if field.startswith("netdev="):
                                        new_arg.append("netdev=net_{vmname}")
                                    elif field.startswith("mac="):
                                        new_arg.append("mac={mac}")
                                    else:
                                        new_arg.append(field)
                                arg = ",".join(new_arg)

                            new_start_args.append(arg)
                        cmdline = ["qemu-system-x86_64"]
                        cmdline.extend(new_start_args)
            except Exception as ex:
                raise CuckooMachineError(
                    "Failed to parse machineinfo file: %s (%s)" % (mi, ex))

        vm_arch = getattr(vm_options, "arch", "default")
        arch_config = dict(QEMU_ARGS[vm_arch])
        if not cmdline:
            # Didn't managed to parse from machineinfo.json, so fall-back
            cmdline = arch_config["cmdline"]
        params = dict(QEMU_ARGS["default"]["params"])
        params.update(QEMU_ARGS[vm_arch]["params"])

        params.update({
            "imagepath": os.path.dirname(vm_options.image),
            "snapshot_path": snapshot_path,
            "vmname": vm_info.name,
            "qmp_socket_path": qmp_socket_path,
        })

        # allow some overrides from the vm specific options
        # also do another round of parameter formatting
        for var in ["mac", "kernel", "initrd"]:
            val = getattr(vm_options, var, params.get(var, None))
            if not val:
                continue
            params[var] = val.format(**params)

        # magic arg building
        final_cmdline = [i.format(**params) for i in cmdline]

        if vm_options.snapshot:
            final_cmdline += ["-loadvm", vm_options.snapshot]

        if vm_options.enable_kvm:
            final_cmdline.append("-enable-kvm")

        log.debug("Executing QEMU %r", final_cmdline)
        with open("/tmp/a.sh", "w") as fp:
            fp.write(" ".join(final_cmdline))

        try:
            proc = subprocess.Popen(final_cmdline, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)

            self.qmp = QMPClient(qmp_socket_path)

            # Wait for socket to exist
            ntries = 5
            while ntries > 0:
                if os.path.exists(qmp_socket_path):
                    try:
                        self.qmp.connect()
                    except QMPError as err:
                        proc.kill()
                        raise CuckooMachineError(
                            "QEMU failed to connect to QMP socket: %s" % err)

                time.sleep(3)
                ntries -= 1

            if not os.path.exists(qmp_socket_path):
                proc.kill()
                raise CuckooMachineError(
                    "QEMU failed to connect to QMP socket: %s" %
                    qmp_socket_path)

            self.state[vm_info.name] = proc
            self.qmp_socket_paths[vm_info.name] = qmp_socket_path
        except OSError as e:
            raise CuckooMachineError("QEMU failed starting the machine: %s" % e)

    def stop(self, label):
        """Stop a virtual machine.
        @param label: virtual machine label.
        @raise CuckooMachineError: if unable to stop.
        """
        log.debug("Stopping vm %s" % label)

        vm_info = self.db.view_machine_by_label(label)

        if self._status(vm_info.name) == self.STOPPED:
            raise CuckooMachineError("Trying to stop an already stopped vm %s" % label)

        proc = self.state.get(vm_info.name, None)
        proc.kill()

        stop_me = 0
        while proc.poll() is None:
            if stop_me < config("cuckoo:timeouts:vm_state"):
                time.sleep(1)
                stop_me += 1
            else:
                log.debug("Stopping vm %s timeouted. Killing" % label)
                proc.terminate()
                time.sleep(1)

        # if proc.returncode != 0 and stop_me < config("cuckoo:timeouts:vm_state"):
        #     log.debug("QEMU exited with error powering off the machine")

        self.state[vm_info.name] = None

        qmp_socket_path = self.qmp_socket_paths[vm_info.name]
        del self.qmp_socket_paths[vm_info.name]
        os.unlink(qmp_socket_path)

    def _status(self, name):
        """Get current status of a vm.
        @param name: virtual machine name.
        @return: status string.
        """
        p = self.state.get(name, None)
        if p is not None:
            return self.RUNNING
        return self.STOPPED
