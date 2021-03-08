#!/usr/bin/env python
# -*- coding: utf-8 -*-

from functools import update_wrapper, wraps


def disable(func):
    '''
    Disable a decorator by re-assigning the decorator's name
    to this function. For example, to turn off memoization:

    >>> memo = disable

    '''
    def wrapper(*args, **kwargs):
        return func(*args)
    return wrapper


def decorator(func):
    '''
    Decorate a decorator so that it inherits the docstrings
    and stuff from the function it's decorating.
    '''
    @wraps(func)
    def wrapper(*args, **kwargs):
        print('function {} started'.format(func.__doc__))
        return func(*args, **kwargs)
    return wrapper


def countcalls(func):
    '''Decorator that counts calls made to the function decorated.'''
    @wraps(func)
    def wrapper(*args, **kwargs):
        result = func(*args, **kwargs)
        wrapper.calls += 1
        return result
    wrapper.calls = 0
    return wrapper

def memo(func):
    '''
    Memoize a function so that it caches all return values for
    faster future lookups.
    '''
    cache = {}
    @wraps(func)
    def wrapper(*args):
        if args in cache:
            return cache[args]
        
        result = func(*args)
        cache[args] = result
        return result 
    return wrapper


def n_ary(func):
    '''
    Given binary function f(x, y), return an n_ary function such
    that f(x, y, z) = f(x, f(y,z)), etc. Also allow f(x) = x.
    '''
    @wraps(func)
    def wrapper(x, *args):
        if not args:
            return x 
        else:
            return func(x, wrapper(*args))
    return wrapper


def trace(line):
    '''Trace calls made to function decorated.

    @trace("____")
    def fib(n):
        ....

    >>> fib(3)
     --> fib(3)
    ____ --> fib(2)
    ________ --> fib(1)
    ________ <-- fib(1) == 1
    ________ --> fib(0)
    ________ <-- fib(0) == 1
    ____ <-- fib(2) == 2
    ____ --> fib(1)
    ____ <-- fib(1) == 1
     <-- fib(3) == 3

    '''
    def trace_it(func):
        @wraps(func)
        def wrapper(*args):
            print(line*wrapper.trace, '-->{}({})'.format(func.__name__, *args))
            wrapper.trace += 1
            result = func(*args)
            wrapper.trace -= 1
            print(line*wrapper.trace, '<--{}({})=={}'.format(func.__name__, *args, result))
            return result
        wrapper.trace = 0
            
        return wrapper
    return trace_it


@memo
@countcalls
@n_ary
def foo(a, b):
    return a + b


@countcalls
@memo
@n_ary
def bar(a, b):
    return a * b


@countcalls
@trace("####")
@memo
def fib(n):
    """Some doc"""
    return 1 if n <= 1 else fib(n-1) + fib(n-2)


def main():
    print (foo(4, 3))
    print (foo(4, 3, 2))
    print (foo(4, 3))
    print ("foo was called", foo.calls, "times")

    print (bar(4, 3))
    print (bar(4, 3, 2))
    print (bar(4, 3, 2, 1))
    print ("bar was called", bar.calls, "times")

    print (fib.__doc__)
    fib(3)
    print (fib.calls, 'calls made')

    
if __name__ == '__main__':
    main()
