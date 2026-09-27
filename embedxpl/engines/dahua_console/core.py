import os
from collections import defaultdict
from threading import Thread

import gevent
from loguru import logger
from gevent.pool import Pool as geventPool

from .data import Data, SnapshotPipeline
from .pocs import get_poc_dict
from .utils import color, common, fingerprint, port_scan, status_bar, timer


@common.singleton
class Core:

    def __init__(self, config):
        self.config = config
        self.data = Data(config)
        self.snapshot_pipeline = SnapshotPipeline(config)
        self.poc_dict = get_poc_dict(self.config)

    def finish(self):
        return (self.data.done >= self.data.total) and (
            self.snapshot_pipeline.task_count <= 0)

    def report(self):
        results_file = os.path.join(self.config.out_dir, self.config.vulnerable)
        if not os.path.exists(results_file):
            return
        with open(results_file, "r") as f:
            items = [l.strip().split(",") for l in f if l.strip()]
        if not items:
            return
        results = defaultdict(lambda: defaultdict(int))
        for i in items:
            dev = i[2].split("-")[0]
            vul = i[-1]
            results[dev][vul] += 1
        total = len(items)
        max_cnt = max(v for d in results.values() for v in d.values())
        print("\n")
        print("-" * 19, "REPORT", "-" * 19)
        for dev in results:
            vuls = list(results[dev].items())
            dev_sum = sum(c for _, c in vuls)
            print(color.red(f"{dev} {dev_sum}", "bright"))
            for vul_name, vul_count in vuls:
                blocks = int(vul_count / max_cnt * 25)
                print(color.green(f"{vul_name:>28} | {'▥' * blocks} {vul_count}"))
        print(color.yellow(f"{'sum: ' + str(total):>46}", "bright"), flush=True)
        print("-" * 46)
        print("\n")

    def _scan_port(self, ip, port):
        if port_scan(ip, port, self.config.timeout):
            logger.info(f"{ip} port {port} is open")
            if product := fingerprint(ip, port, self.config):
                logger.info(f"{ip}:{port} is {product}")
                verified = False
                for poc in self.poc_dict[product]:
                    if results := poc.verify(ip, port):
                        verified = True
                        self.data.add_found()
                        self.data.add_vulnerable(results[:6])
                        if not self.config.disable_snapshot:
                            self.snapshot_pipeline.put((poc.exploit, results))
                if not verified:
                    self.data.add_not_vulnerable([ip, str(port), product])

    def _scan(self, target):
        items = target.split(":")
        ip = items[0]
        ports = [items[1]] if len(items) > 1 else self.config.ports
        jobs = [gevent.spawn(self._scan_port, ip, port) for port in ports]
        gevent.joinall(jobs)
        self.data.add_done()
        self.data.record_running_state()

    def run(self):
        logger.info(f"running at {timer.get_time_formatted()}")
        logger.info(f"config is {self.config}")
        try:
            self.status_bar_thread = Thread(target=status_bar, args=[self], daemon=True)
            self.status_bar_thread.start()
            if not self.config.disable_snapshot:
                self.snap_thread = Thread(
                    target=self.snapshot_pipeline.process, args=[self], daemon=True)
                self.snap_thread.start()
            scan_pool = geventPool(self.config.th_num)
            for ip in self.data.ip_generator:
                scan_pool.start(gevent.spawn(self._scan, ip))
            scan_pool.join()
            self.status_bar_thread.join()
            self.report()
        except KeyboardInterrupt:
            pass
        except Exception as e:
            logger.error(e)
