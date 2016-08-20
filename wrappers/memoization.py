
import pickle

from functools import wraps


CACHE_STORAGE = ('redis', 'simple')

# Number of seconds before timing out.
DEFAULT_TIMEOUT = 60 * 5


class CacheStrategy(object):
    def __init__(self, cache_key_prefix=""):
        self.cache_key_prefix = cache_key_prefix

    def cache_with_memoization(timeout=CACHE_DEFAULT_TIMEOUT):
        """
        Decorator for functions that use the cache.
        This will memoize args and kwargs (using __str__). Note that this will treat
        unique instances of non-primitives as separate.
        """
        def _decorator(run_function):
            @functools.wraps(run_function)
            def _caller(*args, **kwargs):
                # Check for cached response.
                cache = _get_redis_connection()
                key = get_key(run_function.__name__, *args, **kwargs)
                cached_response = cache.get(key)
                if cached_response:
                    unpickled_response = pickle.loads(cached_response)
                    return unpickled_response

                # Execute function and cache pickled response.
                response = run_function(*args, **kwargs)
                picked_response = pickle.dumps(response)
                cache.setex(key, picked_response, timeout)
                return response

            return _caller
        return _decorator

    def get_key(self, function_name, *args, **kwargs):
        """
        Create a consistent cache key based off of __str__ representation of args
        and kwargs. Ignore all arguments that evaluate to False.
        """
        return "{}:{}:{}:{}".format(
            self.cache_key_prefix,
            function_name,
            tuple(arg for arg in args if arg),
            "&".join("{}={}".format(k, v) for k, v in sorted(kwargs.iteritems()) if v)
        )

    def invalidate_key(self, key):
        """Delete cached function with methods."""
        self.cache.expire(key, 0)


class RedisCacheStrategy(CacheStrategy):
    pass


class SimpleStrategy(CacheStrategy):
    pass
