# -*- coding: utf-8 -*-
def get_callback_function(func, default_function=None, default_return=None):
    if (func is None and default_function is None) or not callable(func):
        func_return = func if func is not None else default_return

        def return_func(input, **kwargs):
            return func_return

        return return_func
    return func if func is not None else default_function


class TokenHelper(object):
    def __init__(self, jwt_config=None):
        if jwt_config is None:
            jwt_config = {}
        self.jwt_secret = get_callback_function(jwt_config.get('secret', None))
        self.jwt_algorithm = get_callback_function(jwt_config.get('algorithm', None))
        self.jwt_expired = get_callback_function(jwt_config.get('expired', None))
        self.jwt_leeway = get_callback_function(jwt_config.get('leeway', None))
