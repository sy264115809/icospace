class Limiter:

    def __init__(self, redis_cli, keyfunc, limit, period):
        self._redis_cli = redis_cli
        self._keyfunc = keyfunc
        self._limit = limit
        self._period = period

    def touch(self):
        key = self._keyfunc()
        try:
            current = self._redis_cli.get(key)
            if current is not None and int(current) >= self._limit:
                return False
            else:
                value = self._redis_cli.incr(key)
                if value == 1:
                    self._redis_cli.expire(key, self._period)
                return True
        except Exception as e:
            return False

    def reset(self):
        self._redis_cli.delete(self._keyfunc())
