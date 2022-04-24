#!env python3

import argparse
import json
import logging
import os
import sys
import itertools

from deepdiff import DeepDiff
from deepdiff.helper import CannotCompare
from pprint import pprint


logging.basicConfig()
log = logging.getLogger(os.path.basename(sys.argv[0]))
# log.setLevel(logging.INFO)
log.setLevel(logging.DEBUG)


VOL_KEYS = ['psxview', 'getsids', 'timers', 'callbacks',
            'netscan', 'yarascan', 'handles', 'devicetree',
            'privs', 'pslist', 'ssdt', 'malfind', 'modscan',
            'svcscan', 'dlllist', 'mutantscan', 'ldrmodules']


def try_load_json(file_path):

    json_data = None

    try:
        with open(file_path, 'r') as fp:
            json_data = json.load(fp)
    except IOError as ex:
        log.debug("Failed to open file %s: %s",
                  file_path, str(ex))
        raise ex
    except Exception as ex:
        log.debug("Error loading JSON from %s: %s",
                  file_path, str(ex))

    if json_data is None:
        raise ValueError("Invalid data in JSON file %s" % file_path)

    if not isinstance(json_data, dict):
        raise ValueError("Error JSON from %s is not a dictionary" % file_path)

    return json_data


def dict_hash(d):
    return hash(tuple(sorted(
        [(a, tuple(b) if isinstance(b, (list, dict)) else b)
         for a, b in d.items()])))


def compare_json_list(a, b, key_chain=list()):
    assert isinstance(a, list)
    assert isinstance(b, list)

    if len(a) != len(b):
        log.debug("%s - Lengths differ %d != %d",
                  ":".join(key_chain), len(a), len(b))

    if len(a) == 0:
        print("A is empty")
        return

    if len(b) == 0:
        print("B is empty")
        return

    if isinstance(a[0], dict):
        for a_index in range(len(a)):
            for b_index in range(len(b)):
                assert isinstance(a[a_index], dict)
                assert isinstance(b[b_index], dict)

                if dict_hash(a[a_index]) != dict_hash(b[b_index]):
                    print("A[%d] != B[%d]" % (a_index, b_index))





def compare_json_dict(a, b, key_chain=list()):
    assert isinstance(a, dict)
    assert isinstance(b, dict)

    log.debug("Key chain: %s", key_chain)
    a_keys = set(a.keys())
    b_keys = set(b.keys())

    print(a_keys)
    return

    only_a = a_keys - b_keys
    only_b = b_keys - a_keys

    if only_a:
        print("Only in a: %s" % str(only_a))

    if only_b:
        print("Only in b: %s" % str(only_b))

    for key in a.keys():
        if key not in b:
            log.debug("Key %s is not in b", key)
            continue

        if not isinstance(a[key], type(b[key])):
            log.error("Types for key %s differs", key)
            continue

        if isinstance(a[key], dict):
            compare_json_dict(a[key], b[key], key_chain + [key])
        elif isinstance(a[key], list):
            compare_json_list(a[key], b[key], key_chain + [key])
        else:
            # Directly compare values
            if a[key] != b[key]:
                print("%s differs: %s != %s" %
                      (",".join(key_chain), a[key], b[key]))


def compare_by_field(field):

    def compare_func(x, y, level=None):
        try:
            return x[field] == y[field]
        except Exception:
            raise CannotCompare() from None

    return compare_func


def compare_by_fields(fields):

    def compare_func(x, y, level=None):
        try:
            matched = True
            for field in fields:
                print("x[%s] (%s) != y[%s] (%s) => %s " % (
                    field, x[field],
                    field, y[field],
                    x[field] != y[field]))
                if x[field] != y[field]:
                    matched = False
                    break
            return matched
        except Exception as ex:
            raise CannotCompare() from None

    return compare_func


def compare_list(a, b, compare_func):

    added = b[:]
    deleted = list()
    both = list()

    for _a in a:
        seen = None
        for _b in b:
            if compare_func(_a, _b):
                seen = _b
                break

        if seen is None:
            deleted.append(_a)
        else:
            both.append(_a)
            try:
                added.remove(seen)
            except ValueError:
                # Sometimes seems to need to remove original, not seen value??
                try:
                    added.remove(_a)
                except ValueError:
                    pass

    return {'added': added, 'deleted': deleted, 'both': both}


def proc_is_hidden(pinfo):

    CONDS = [
        {"pslist": "True",
         "psscan": "True",
         "thrdproc": "False"},
        {"pslist": "False",
         "psscan": "False"}
        ]

    is_hidden = True
    for cond in CONDS:
        is_hidden = True
        for k, v in cond.items():
            if pinfo.get(k, None) is None or pinfo.get(k) != v:
                is_hidden = False
                break
        if is_hidden:
            break

    return is_hidden


def psxview_hidden_procs(info):

    hidden = list()
    psxview = info.get('psxview', {})
    for proc in psxview.get('data', []):
        if proc_is_hidden(proc):
            hidden.append(proc)

    return hidden


def compare_psxview(a,b):
    '''
    Looks something like:
        {
        "config": {
            "filter": false
        },
        "data": [
            {
            "csrss": "False",
            "deskthrd": "False",
            "process_id": 1792,
            "process_name": "svchost.exe",
            "pslist": "False",
            "pspcid": "False",
            "psscan": "True",
            "session": "False",
            "thrdproc": "False"
            },
            {
            ...
    '''

    diffs = compare_list(a["data"], b["data"],
                         compare_by_field("process_id"))

    return diffs


def compare_devicetree(a, b):
    '''
    Looks something like:
        {
        "config": {
            "filter": true
        },
        "data": [
            {
            "devices": [
                {
                "device_name": "LanmanServer",
                "device_offset": "0xfffffa800297e260",
                "device_type": "FILE_DEVICE_NETWORK",
                "devices_attached": []
                }
            ],
            "driver_name": "\\FileSystem\\srv",
            "driver_offset": "0x3e24c060"
            },
            ...
    '''

    a_devices = list(sum([x["devices"] for x in a['data']], []))
    b_devices = list(sum([x["devices"] for x in a['data']], []))
    diffs = compare_list(a_devices, b_devices,
                         compare_by_fields(["device_name", "device_type"]))

    return diffs


def compare_volatility_json(a, b):
    assert isinstance(a, dict)
    assert isinstance(b, dict)

    return {
        'devicetree': compare_devicetree(a["devicetree"], b["devicetree"]),
        'psxview': compare_psxview(a["psxview"], b["psxview"]),
        'hidden_processes': psxview_hidden_procs(a) + psxview_hidden_procs(b),
    }


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-d", "--debug", help='Enable debug log',
        action='store_true')

    parser.add_argument(
        "files", metavar='files', type=str,
        nargs='+', help="Files to compare")

    args = parser.parse_args()

    if args.debug:
        log.setLevel(logging.DEBUG)

    if len(args.files) != 2:
        log.error("Nothing to do, no files specified")
        sys.exit(1)

    try:
        json_data_1 = try_load_json(args.files[0])
        json_data_2 = try_load_json(args.files[1])
    except (ValueError, IOError) as ex:
        log.error("Error: %s", ex)
        sys.exit(1)

    pprint(compare_volatility_json(json_data_1, json_data_2))
    # pprint(DeepDiff(json_data_1, json_data_2, ignore_order=True))

if __name__ == '__main__':
    main()
