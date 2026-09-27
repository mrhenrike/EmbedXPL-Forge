"""Data pipeline: IP generation, result writing, progress tracking."""
import hashlib
import itertools
import os
import time
from concurrent.futures import ThreadPoolExecutor
from queue import Queue
from threading import Lock, RLock, Thread

from loguru import logger

from .utils import common, timer, net


@common.singleton
class Data:

    def __init__(self, config):
        self.config = config
        self.create_time = timer.get_time_stamp()
        self.runned_time = 0
        self.taskid = hashlib.md5(
            (self.config.in_file + self.config.out_dir).encode("utf-8")
        ).hexdigest()
        self.total = 0
        self.done = 0
        self.found = 0
        self.total_lock = Lock()
        self.found_lock = Lock()
        self.done_lock = Lock()
        self.vulnerable_lock = Lock()
        self.not_vulneralbe_lock = Lock()
        self.preprocess()

    def _load_state_from_disk(self):
        if self.config.no_resume:
            return
        state_file = os.path.join(self.config.out_dir, f".{self.taskid}")
        if os.path.exists(state_file):
            with open(state_file, "r") as f:
                if line := f.readline().strip():
                    _done, _found, _runned_time = line.split(",")
                    self.done = int(_done)
                    self.found = int(_found)
                    self.runned_time = float(_runned_time)

    def _cal_total(self):
        with open(self.config.in_file, "r") as f:
            for line in f:
                if (s := line.strip()) and not line.startswith("#"):
                    self.add_total(net.get_ip_seg_len(s))

    def _generate_ip(self):
        current = 0
        remain_gen = None
        with open(self.config.in_file, "r") as f:
            if self.done:
                for line in f:
                    if (s := line.strip()) and not line.startswith("#"):
                        seg_len = net.get_ip_seg_len(s)
                        current += seg_len
                        if current == self.done:
                            break
                        elif current < self.done:
                            continue
                        else:
                            skip = self.done - (current - seg_len)
                            remain_gen = itertools.islice(net.get_all_ip(s), skip, None)
                            break
                if remain_gen:
                    yield from remain_gen
            for line in f:
                if (s := line.strip()) and not line.startswith("#"):
                    yield from net.get_all_ip(s)

    def preprocess(self):
        out = self.config.out_dir
        self.vulnerable = open(os.path.join(out, self.config.vulnerable), "a")
        self.not_vulneralbe = open(os.path.join(out, self.config.not_vulnerable), "a")
        self._load_state_from_disk()
        t = Thread(target=self._cal_total)
        t.start()
        self.ip_generator = self._generate_ip()
        t.join()

    def add_total(self, item=1):
        with self.total_lock:
            self.total += item if isinstance(item, int) else sum(item)

    def add_found(self, item=1):
        with self.found_lock:
            self.found += item if isinstance(item, int) else sum(item)

    def add_done(self, item=1):
        with self.done_lock:
            self.done += item if isinstance(item, int) else sum(item)

    def add_vulnerable(self, item):
        with self.vulnerable_lock:
            self.vulnerable.write(",".join(item) + "\n")
            self.vulnerable.flush()

    def add_not_vulnerable(self, item):
        with self.not_vulneralbe_lock:
            self.not_vulneralbe.write(",".join(item) + "\n")
            self.not_vulneralbe.flush()

    def record_running_state(self):
        if self.done % 20 == 0:
            elapsed = self.runned_time + timer.get_time_stamp() - self.create_time
            state = os.path.join(self.config.out_dir, f".{self.taskid}")
            with open(state, "w") as f:
                f.write(f"{self.done},{self.found},{elapsed}")

    def __del__(self):
        try:
            self.record_running_state()
            self.vulnerable.close()
            self.not_vulneralbe.close()
        except Exception as e:
            logger.error(e)


@common.singleton
class SnapshotPipeline:

    def __init__(self, config):
        self.config = config
        self.var_lock = RLock()
        self.pipeline = Queue(self.config.th_num * 2)
        self.workers = ThreadPoolExecutor(self.config.th_num)
        snap_dir = os.path.join(self.config.out_dir, self.config.snapshots)
        self.done = len(os.listdir(snap_dir))
        self.task_count = 0
        self.task_count_lock = Lock()

    def put(self, msg):
        self.pipeline.put(msg)

    def empty(self):
        return self.pipeline.empty()

    def get_done(self):
        with self.var_lock:
            return self.done

    def add_done(self, num=1):
        with self.var_lock:
            self.done += num

    def _snapshot(self, exploit_func, results):
        if res := exploit_func(results):
            self.add_done(res)
        with self.task_count_lock:
            self.task_count -= 1

    def process(self, core):
        while not core.finish():
            try:
                exploit_func, results = self.pipeline.get(timeout=5)
            except Exception:
                continue
            self.workers.submit(self._snapshot, exploit_func, results)
            with self.task_count_lock:
                self.task_count += 1
            time.sleep(0.1)
