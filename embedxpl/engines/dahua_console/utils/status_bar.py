"""Live status bar rendered to stdout during scanning."""
import random
import time

from . import timer
from .color import color


def _bar():
    """Return a closure that prints one status bar frame to stdout."""
    cidx = [0]
    icon_list = random.choice([
        '⇐⇖⇑⇗⇒⇘⇓⇙',
        '⣾⣷⣯⣟⡿⢿⣻⣽',
        '⠁⠉⠙⠛⠚⠒⠂⠃⠋⠛⠙⠘⠐⠒⠓⠛⠋⠉⠈⠘⠚⠛⠓⠃',
        '⠿⠷⠯⠟⠻⠽⠾⠿⠷⠧⠇⠃⠁ ⠁⠉⠙⠹⠽',
        '▁▂▃▅▆▇▆▅▃▂▁ ',
        '➩➫➬',
        '😶😶😕😕😦😦😧😧😨😨😀😀😃😃😄😄😆😆😊😊😉😉',
        '🧍🧍🚶🚶🤾🤾🏃🏃🤾🤾🚶🚶',
        '🕛🕐🕑🕒🕓🕔🕕🕖🕗🕘🕙🕚',
    ])

    def wrapper(total, done, found, snapshot, time_used):
        # Spinning icon
        icon = color.green(icon_list[cidx[0]], 'bright')
        cidx[0] = (cidx[0] + 1) % len(icon_list)
        icon = f'[{icon}]'

        # ETA
        time_pred = time_used * (total / (done + 0.001))   # avoid divide-by-zero
        time_used_str = color.cyan(timer.time_formatter(time_used), 'bright')
        time_pred_str = color.white(timer.time_formatter(time_pred), 'bright')
        _time = f'Time: {time_used_str}/{time_pred_str}'

        # Progress counters
        _total   = color.blue(total, 'bright')
        _done    = color.blue(done, 'bright')
        _pct     = color.yellow(f'{round(done / (total + 0.001) * 100, 1)}%', 'bright')
        _found   = 'Found '    + color.red(found,    'bright') if found    else ''
        _snap    = 'Snapshot ' + color.red(snapshot, 'bright') if snapshot else ''
        count = f'{_done}/{_total}({_pct}) {_found} {_snap}'

        print(f'\r{icon} {count} {_time}        ', end='')

    return wrapper


def status_bar(core):
    """Continuously render the status bar until the scan finishes."""
    bar = _bar()

    def print_bar():
        bar(
            core.data.total,
            core.data.done,
            core.data.found,
            core.snapshot_pipeline.get_done(),
            timer.get_time_stamp() - core.data.create_time + core.data.runned_time,
        )

    while not core.finish():
        print_bar()
        time.sleep(0.1)
    print_bar()
