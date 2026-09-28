"""Base class for all POC modules."""
import os
import requests
from collections import namedtuple
from loguru import logger


class POCTemplate:
    """Template that every individual POC must inherit from."""

    level = namedtuple('level', 'high medium low')('high', 'medium', 'low')
    poc_classes = []

    @staticmethod
    def register_poc(cls):
        """Register a POC class so the scanner can discover and use it."""
        POCTemplate.poc_classes.append(cls)

    def __init__(self, config):
        self.config = config
        self.name = self.get_file_name(__file__)
        self.product = 'base'
        self.product_version = ''
        self.ref = ''
        self.level = self.level.low
        self.desc = ''
        self.session = requests.Session()
        self.session.headers.update({
            'Connection': 'keep-alive',
            'User-Agent': self.config.user_agent,
        })

    def get_file_name(self, file):
        """Return the stem of the given file path (used as POC name)."""
        return os.path.basename(file).split('.')[0]

    def verify(self, ip, port):
        """
        Probe the target for this vulnerability.

        Returns:
            tuple (ip, port, product, user, password, poc_name) on success,
            None on failure.
        """
        pass

    def _snapshot(self, url, img_file_name, auth=None) -> int:
        """Download an image from *url* and save it to the snapshots directory."""
        img_path = os.path.join(self.config.out_dir, self.config.snapshots, img_file_name)
        try:
            kwargs = dict(timeout=self.config.timeout, verify=False, stream=True)
            if auth:
                kwargs['auth'] = auth
            res = self.session.get(url, **kwargs)
            if res.status_code == 200 and 'head' not in res.text:
                with open(img_path, 'wb') as f:
                    for chunk in res.iter_content(10240):
                        f.write(chunk)
                return 1
        except Exception as e:
            logger.error(e)
        return 0

    def exploit(self, results: tuple) -> int:
        """Post-exploitation: capture a snapshot. Returns number of snapshots saved."""
        return 0
