import functools

ACCEPT = 0
DROP = 1
REJECT = 2
MANGLE = 3
EXCEPTION = 4
INVALID = 5

def pyfilter(func):
    """
    Decorator to mark functions that will be used in the proxy.
    Stores the function reference in a global registry.
    """
    if not hasattr(pyfilter, "registry"):
        pyfilter.registry = set()
    
    pyfilter.registry.add(func.__name__)
    
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)
    
    return wrapper

def get_pyfilters():
    """Returns the list of functions marked with @pyfilter."""
    return list(pyfilter.registry)










