"""Utility stuff"""


import multiprocessing
import logging
import os
import random
import time
from functools import partial
from random import choice, shuffle
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from multiprocessing import Process
from .types_ import Library

logger = logging.getLogger("synthesizer.utils")

def bytes_to_qwords(bytes_: List[int]) -> List[int]:
    qwords = []
    for i in range(0, len(bytes_), 8):
        qword = 0
        for j in range(8):
            qword = qword | bytes_[i+j] << j
        qwords.append(qword)
    return qwords

def min_or_some(a: int, b: Optional[int]) -> int:
    """Return minimal element or the element set"""
    if b is None:
        return a
    return min(a, b)


def to_int(num: Union[int, str]) -> int:
    if isinstance(num, int):
        return num
    if isinstance(num, str):
        if num.startswith("0x") or num[-1] == "h":
            return int(num, 16)
        try:
            return int(num, 16)
        except:
            logger.warning(f"{num} appears to be in decimal notation")
            return int(num, 10)


def is_timeout(start: float, timeout: Optional[int]) -> bool:
    if timeout is None:
        return False
    if time.time() - start <= timeout:
        return False
    return True


def ram_stats() -> Tuple[int, int, int]:
    total, used, free = map(int, os.popen('free -t -m').readlines()[-1].split()[1:])
    return (total, used, free)


def get_library_of_addr(addr: int, libraries: List[Library]) -> Optional[Library]:
    """
    Returns name of the library to which the address belongs.
    Requires the address to be not an offset but a 'rebased' address
    """
    sorted_libs = sorted(libraries, key=lambda lib: lib.load_address)
    for lib in sorted_libs[::-1]:
        if addr > lib.load_address:
            return lib
    return None


class Paralleliser(object):
    # tasks = Tuple[func_to_execute, task_group_str]
    # if one member of the task_group succeeds, others are not started anymore
    def __init__(self, tasks: 'List[Tuple[partial[Any], str]]', max_processes: int = 0):
        self.functions: 'List[partial[Any]]' = [t for (t, _) in tasks]
        self.task_groups: List[str] = [tg for (_, tg) in tasks]

        self.process_to_task_group: Dict[Process, str] = dict()
        self.process_to_task_id: Dict[Process, int] = dict()
        self.task_group_results: Dict[str, Any] = dict()

        if not max_processes:
            max_processes = multiprocessing.cpu_count()
        self.max_processes = max_processes

    def execute(self, timeout: Optional[int] = None) -> List[Any]:
        # initialise parallel data structures
        manager = multiprocessing.Manager()
        results: List[Any] = manager.list()
        processes: List[Process] = [None] * len(self.functions) # type: ignore

        # set task_groups to not-finished
        task_group_states = {}
        for task in self.task_groups:
            task_group_states[task] = 0

        # initialise process mappings
        process_to_task_group: Dict[Process, str] = dict()
        process_to_index: Dict[Process, int]= dict()

        # initialise processes
        for i in range(len(processes)):
            # extend results
            results.append(None)

            # create process
            processes[i] = multiprocessing.Process(target=self.functions[i], args=(results, i))

            # map process to process index
            process_to_index[processes[i]] = i

            # choose task group randomly
            process_to_task_group[processes[i]] = self.task_groups[i]

        # initialise data structures
        active_processes: Set[Process] = set()
        done: Set[Process] = set()
        process_counter = -1

        # random permutation of process indexes
        random_process_indices = list(range(len(processes)))
        shuffle(random_process_indices)

        start_time = time.time()
        # iterate until all processes have been processed
        while len(done) < len(processes) and not is_timeout(start_time, timeout):
            # add more processes, if # processes < # cpu cores and there are processes remaining
            while len(active_processes) < self.max_processes and process_counter < len(processes) - 1:
                # increase index
                process_counter += 1
                # random process index
                random_process_index = random_process_indices.pop()
                # get next process
                process = processes[random_process_index]

                # get process' task group
                task_group = process_to_task_group[process]

                # print random_process_index, task_group

                # process' taskgroup has been solved
                if task_group_states[task_group]:
                    done.add(process)

                # get next process
                if process in done:
                    continue

                # start process
                process.start()

                # add to active processes
                active_processes.add(process)

            # if there are active processes
            if active_processes:
                # choose random process
                process = choice(list(active_processes.copy()))

                # process has been terminated
                if not process.is_alive():
                    # get process index
                    process_index = process_to_index[process]
                    # get result
                    result = results[process_index]

                    # if process terminated with a result:
                    if result:
                        # get process' task group
                        task_group = process_to_task_group[process]
                        # set task group to finished
                        task_group_states[task_group] = 1

                        # store task group's result
                        self.task_group_results[task_group] = result

                        # terminate active processes in current task group
                        for process in active_processes.copy():
                            # process is in the same task group?
                            if task_group == process_to_task_group[process]:
                                # kill process
                                process.terminate()
                                # add to done
                                done.add(process)
                                # remove from active processes
                                active_processes.remove(process)

                    # delete process
                    else:
                        # add to done
                        done.add(process)
                        # remove from active processes
                        active_processes.remove(process)

        if is_timeout(start_time, timeout):
            # if we terminated, kill all running processes
            # and discard their intermediate results
            while len(active_processes):
                p = active_processes.pop()
                if p.is_alive():
                    p.terminate()

        return results
