# python bytecode analysis plugin for Hex-Rays Decompiler
# Copyright (c) 2025
# NONG <ndj8886@163.com>
# Report bugs and issues on <https://github.com/nongdajun/ida-pyc/issues>
# All rights reserved.
#
# ==============================================================================
#
# This file is part of ida-pyc.
#
# ida-pyc is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# ==============================================================================

import idaapi
import os, sys

def PROCESSOR_ENTRY():
    pyc_info = getattr(idaapi, 'pyc_info', None)
    if not pyc_info:
        return

    sys.path.append(f"{os.path.dirname(__file__)}/pyc-procs")

    tuple_version, is_pypy = pyc_info[0], pyc_info[4]
    if tuple_version[0]==3:
        m = __import__('pyc_v3')
    else:
        m = __import__('pyc_simple')

    return m.PROCESSOR_ENTRY()

