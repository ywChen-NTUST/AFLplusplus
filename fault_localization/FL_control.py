import socket
import socketserver
import os
from enum import Enum
from struct import unpack, pack, calcsize
import threading
from typing import Dict, List
from copy import deepcopy
from collections import Counter
import pickle
import time

import numpy as np
import lief

class FLCommand(Enum):
    FL_DISABLE = 0
    FL_RECORD = 1

class FLStatus(Enum):
    FL_NORMAL = 0
    FL_CRASH = 1
    FL_ERROR = 2

FL_DATA_SOCKET = "/tmp/FL_data.sock"
FL_CONTROL_SOCKET_PREFIX = "/tmp/FL_command_" # /tmp/FL_command_<pid>.sock
FL_DATA_RECV_SIZE = 16 * 1024

"""
{
    "normal": {
        <pid>: [<loc1>, <loc2>, ...],
        ...
    },
    "crash": {
        ...
    },
    "error": {
        ...
    },
    "running": {
        ...
    },
}
"""
all_info: Dict[str, Dict[int, List[int]]] = {
    "normal": {},
    "crash": {},
    "error": {},
    "running": {}
}
data_thread: threading.Thread = None
FL_data_server: socketserver.BaseServer = None
analyze_binary: lief.ELF.Binary = None

has_first_data: bool = False
has_first_crash: bool = False

def cleanup():
    try:
        os.remove(FL_DATA_SOCKET)
        if FL_data_server:
            FL_data_server.shutdown()
        if data_thread:
            data_thread.join()
    except:
        pass

class FL_Data_Handler(socketserver.StreamRequestHandler):
    def get_base_address(self, pid: int, binary_path: str) -> int:
        with open(f"/proc/{pid}/maps", "r") as f:
            for line in f:
                if binary_path in line:
                    parts = line.split()
                    if len(parts) > 0:
                        base_address = int(parts[0].split('-')[0], 16)
                        return base_address
        raise RuntimeError(f"Base address not found for PID {pid}")

    def setup(self):
        global analyze_binary
        SO_PEERCRED = 17
        creds = self.request.getsockopt(socket.SOL_SOCKET, SO_PEERCRED, calcsize('3i'))
        pid, uid, gid = unpack('3i', creds)

        analyze_binary_path = None
        try:
            analyze_binary_path = os.readlink(f"/proc/{pid}/exe")
        except FileNotFoundError:
            raise FileNotFoundError(f"something wrong with pid {pid}")

        analyze_binary = lief.parse(analyze_binary_path)
        if analyze_binary.is_pie:
            self.base_address = self.get_base_address(pid, analyze_binary_path)
        else:
            self.base_address = 0x0
        # print(f"base address for PID {pid} is {hex(self.base_address)}")

    def handle(self):
        global all_info, has_first_data, has_first_crash
        stophandling: bool = False
        while not stophandling:
            data = self.request.recv(FL_DATA_RECV_SIZE)
            for i in range(0, len(data), 16):
                pid, loc = unpack("<QQ", data[i:i+16])

                if has_first_data is False:
                    has_first_data = True
                    print("First data received at",
                          time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                    )

                if (loc & (1 << 63)) == 0:
                    loc = loc - self.base_address
                    locs = all_info["running"].get(pid)
                    if locs is None:
                        all_info["running"][pid] = [loc]
                    else:
                        all_info["running"][pid].append(loc)
                else:
                    locs = all_info["running"].pop(pid, None)
                    loc = loc & 0x7FFFFFFFFFFFFFFF
                    if locs is not None:
                        if loc == FLStatus.FL_NORMAL.value:
                            all_info["normal"][pid] = locs
                        elif loc == FLStatus.FL_CRASH.value:
                            all_info["crash"][pid] = locs
                            if has_first_crash is False:
                                has_first_crash = True
                                print("First crash received",
                                      time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                                )
                        elif loc == FLStatus.FL_ERROR.value:
                            all_info["error"][pid] = locs
                    # stophandling = True
                    # break

class Thread_UnixStream_Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    pass

def read_fl_data_thread():
    global FL_data_server
    FL_data_server = Thread_UnixStream_Server(FL_DATA_SOCKET, FL_Data_Handler)
    try:
        FL_data_server.serve_forever()
    except KeyboardInterrupt:
        pass

def send_fl_command(pid, command: FLCommand):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(FL_CONTROL_SOCKET_PREFIX + str(pid) + ".sock")
    sock.send(pack("<I", command.value))
    sock.close()

def menu():
    print("1. Disable fault localization")
    print("2. Enable fault localization recording")
    print("3. Analyze")
    print("4. Dump statistics data")
    print("5. Show data distribution")
    print("6. Exit")

def analyze_fault_locataion(normal_info: Dict, crash_info: Dict, topk: int = 5) -> List:
    all_locs = list(
        set([loc for locs in normal_info.values() for loc in locs]) |
        set([loc for locs in crash_info.values() for loc in locs])
    )
    all_locs.sort()
    loc_count_crash = Counter([
        loc for locs in crash_info.values() for loc in list(set(locs))
    ])
    loc_count_normal = Counter([
        loc for locs in normal_info.values() for loc in list(set(locs))
    ])
    loc_count_crash_list = np.asarray(
        [loc_count_crash[loc] for loc in all_locs],
        dtype=np.float64
    )
    loc_count_all_list = np.asarray(
        [loc_count_crash[loc] + loc_count_normal[loc] for loc in all_locs],
        dtype=np.float64
    )

    n_score = loc_count_crash_list / float(len(crash_info))
    s_score = loc_count_crash_list / loc_count_all_list
    n_score_norm = (n_score - np.min(n_score)) / (np.max(n_score) - np.min(n_score))
    s_score_norm = (s_score - np.min(s_score)) / (np.max(s_score) - np.min(s_score))
    l2_norm = np.sqrt(n_score_norm ** 2 + s_score_norm ** 2) / pow(2, 0.5)

    sorted_idx_list = np.argsort(-l2_norm, kind='stable')
    all_locs = np.asarray(all_locs)
    all_locs = all_locs[sorted_idx_list]
    n_score = n_score[sorted_idx_list]
    s_score = s_score[sorted_idx_list]
    n_score_norm = n_score_norm[sorted_idx_list]
    s_score_norm = s_score_norm[sorted_idx_list]
    l2_norm = l2_norm[sorted_idx_list]

    possible_locations = []
    for i in range(min(topk, len(all_locs))):
        possible_locations.append(
            (all_locs[i], n_score[i], s_score[i], n_score_norm[i], s_score_norm[i], l2_norm[i])
        )
    # also returns all elements if them have the same score as the last element
    for i in range(topk, len(all_locs)):
        if l2_norm[i] == l2_norm[topk-1]:
            possible_locations.append(
                (all_locs[i], n_score[i], s_score[i], n_score_norm[i], s_score_norm[i], l2_norm[i])
            )
        else:
            break

    return possible_locations
def show_distribute(info: Dict):
    normal_path_length = [len(locs) for locs in info["normal"].values()]
    crash_path_length = [len(locs) for locs in info["crash"].values()]
    print("Normal path length distribution:")
    print(f"Mean: {np.mean(normal_path_length):.5f}")
    print(f"Median: {np.median(normal_path_length):.5f}")
    print(f"Std: {np.std(normal_path_length):.5f}")
    print(f"Max: {np.max(normal_path_length):.5f}")
    print(f"Min: {np.min(normal_path_length):.5f}")
    print("Crash path length distribution:")
    print(f"Mean: {np.mean(crash_path_length):.5f}")
    print(f"Median: {np.median(crash_path_length):.5f}")
    print(f"Std: {np.std(crash_path_length):.5f}")
    print(f"Max: {np.max(crash_path_length):.5f}")
    print(f"Min: {np.min(crash_path_length):.5f}")

if __name__ == "__main__":
    data_thread = threading.Thread(target = read_fl_data_thread)
    data_thread.start()

    while True:
        menu()
        choice = int(input("Enter your choice: "))
        if choice == 1:
            pid = int(input("Enter the PID of the process: "))
            send_fl_command(pid, FLCommand.FL_DISABLE)
        elif choice == 2:
            pid = int(input("Enter the PID of the process: "))
            send_fl_command(pid, FLCommand.FL_RECORD)
        elif choice == 3:
            print("waiting for analyze ...")
            start_time = time.time_ns()

            # all_info_copy = deepcopy(all_info)
            all_info_copy = all_info

            print("| Status | Count |")
            print("|--------|-------|")
            for status, info in all_info_copy.items():
                print(f"| {status} | {len(info.keys())} |")

            normal_info = all_info_copy["normal"]
            crash_info = all_info_copy["crash"]
            if len(normal_info) == 0 or len(crash_info) == 0:
                print("No enough data")
                continue
            possible_locations = analyze_fault_locataion(normal_info, crash_info)

            end_time = time.time_ns()

            print("| Location | N-Score | S-Score | N-Score-Norm | S-Score-Norm | L2-Norm |")
            print("|----------|---------|---------|--------------|--------------|---------|")
            for loc, n_score, s_score, n_score_norm, s_score_norm, l2_norm in possible_locations:
                funcname = ''
                for f in analyze_binary.functions:
                    if loc >= f.address and loc < f.address + f.size:
                        funcname = f.name
                        break
                print(f"| {hex(loc)} ({funcname}) |", end='')
                print(f" {n_score:.3f} |", end='')
                print(f" {s_score:.3f} |", end='')
                print(f" {n_score_norm:.3f} |", end='')
                print(f" {s_score_norm:.3f} |", end='')
                print(f" {l2_norm:.3f} |")
            print(f"Time elapsed: {(end_time - start_time) / 1e9:.6f} seconds")
        elif choice == 4:
            output = input("Enter the output file name: ").strip()
            print("Dumping data ...")
            # all_info_copy = deepcopy(all_info)
            all_info_copy = all_info
            with open(output, "wb") as f:
                pickle.dump(all_info_copy, f)
        elif choice == 5:
            # all_info_copy = deepcopy(all_info)
            all_info_copy = all_info
            show_distribute(all_info_copy)
        elif choice == 6:
            break
        else:
            print("Invalid choice")

    cleanup()