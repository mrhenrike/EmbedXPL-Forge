"""Global configuration module."""
import os
from collections import namedtuple
from .utils import net


# Default configuration template (rebuilt fresh on each get_config() call)
_DEFAULT_CONFIG = {
    'users': ['admin', 'Admin', 'administrator', 'root', 'user', 'guest'],
    'passwords': [
        'admin', 'admin123', 'admin12345', 'admin@123', 'Admin@123',
        '12345', '123456', '1234567890', 'password', 'pass',
        'asdf1234', 'abc12345', '12345admin', '12345abc',
        'abcd1234', '111111', '888888', '666666', '000000',
        '',           # empty password
    ],
    'ports': [
        80, 81, 82, 83, 84, 85, 88,
        8000, 8001, 8080, 8081, 8085, 8086, 8088, 8090, 8181,
        2051, 9000, 37777, 49152, 55555,
        443, 8443, 8888, 9090,
    ],
    'log':            'log.txt',
    'not_vulnerable': 'not_vulnerable.csv',
    'vulnerable':     'results.csv',
    'snapshots':      'snapshots',
    'wxuid':          '',
    'wxtoken':        '',
}


def get_config(args=None):
    """Build and return a config namedtuple from defaults + CLI args."""
    # Fresh copy every call - avoids mutable module-level state pollution
    cfg = dict(_DEFAULT_CONFIG)
    cfg['user_agent'] = net.get_user_agent()   # rotate UA each run
    cfg['product'] = {}
    cfg['rules']   = set()

    # Load fingerprint rules from rules.csv
    Rule = namedtuple('Rule', ['product', 'path', 'val'])
    rules_file = os.path.join(os.path.dirname(__file__), 'rules.csv')
    with open(rules_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split(',', 2)
            if len(parts) != 3:
                continue
            product, path, val = parts
            cfg['rules'].add(Rule(product, path, val))
            cfg['product'][product] = product

    # Merge CLI args (only non-None values override defaults)
    if args:
        for key, val in vars(args).items():
            if val is not None:
                cfg[key] = val

    Config = namedtuple('Config', cfg.keys())
    return Config(**cfg)
