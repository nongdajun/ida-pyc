import idaapi
import os, sys

def PROCESSOR_ENTRY():
    pyc_info = getattr(idaapi, 'pyc_info', None)
    if not pyc_info:
        return

    sys.path.append(f"{os.path.dirname(__file__)}/pyc-procs")

    tuple_version, is_pypy = pyc_info[0], pyc_info[4]
    if tuple_version[0]==31:
        m = __import__('pyc_v3')
    else:
        m = __import__('pyc_simple')

    return m.PROCESSOR_ENTRY()

