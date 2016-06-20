
import redis

"""This module is meant to provide a distributed locks solution for Celery and Celerybeat.
When running Celerybeat distributed (for redundancy), each instance will spawn the cron tasks
specified when loading the app. In many cases, this is undesirable behavior. One solution is
to use distributed locks so that the intended workload is processed by only one worker. This
module uses Redis as a backend.
"""

DEFAULT_KEY = "dist_lock:unknown"
DEFAULT_TIMEOUT = 300  # Five minutes.

# Connection params.
DB = 1
HOST = "localhost"
PASSWORD = None
PORT = 6379

_redis = None


def _get_redis_connection():
    global _redis
    if _redis is None:
        _redis = redis.Redis(
            host=HOST,
            port=PORT,
            password=PASSWORD,
            db=DB
        )

    return _redis


def distributed_lock(key=DEFAULT_KEY, timeout=DEFAULT_TIMEOUT):
    """Task.run() decorator.
    When applied, will attempt a non-blocking Redis lock, and only execute the wrapped
    method if successful in applying (for timeout duration). If method is called with
    `ignore_lock` keyword argument with value True, bypass setting/checking lock.
    """
    def _decorator(run_function):

        def _caller(*args, **kwargs):
            # Check for `ignore_lock` keyword argument.
            if 'ignore_lock' in kwargs and kwargs['ignore_lock'] == True:
                return run_function(*args, **kwargs)

            # Attempt the lock and return method if successfully applied.
            lock = _get_redis_connection().lock(key, timeout=timeout)
            success = lock.acquire(blocking=False)
            if success:
                return run_function(*args, **kwargs)

        return _caller

    return _decorator


def release_lock(key):
    """Manually release a lock. This may be called when exiting a task.
    """
    success = _get_redis_connection().delete(key)
