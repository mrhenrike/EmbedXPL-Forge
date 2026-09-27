"""Time utilities."""
import time


def get_time_stamp():
    """Return the current Unix timestamp as a float."""
    return time.time()


def get_time_formatted():
    """Return the current local time as a formatted string."""
    return time.strftime('%Y-%m-%d %X', time.localtime())


def run_time(func):
    """Decorator that prints the wall-clock execution time of a function."""
    def wrapper(*args, **kwargs):
        t0 = time.time()
        res = func(*args, **kwargs)
        print(f"\n>Time used: {time_formatter(time.time() - t0)}")
        return res
    return wrapper


def time_formatter(t: float) -> str:
    """Format a duration in seconds into a human-readable string (HH:MM:SS)."""
    if t > 60 * 60: return f"{int(t / (60 * 60))}h " + time_formatter(t % (60 * 60))
    elif t > 60: return f"{int(t / 60)}m " + time_formatter(t % 60)
    else: return f"{int(t)}s"