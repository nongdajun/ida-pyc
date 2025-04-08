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
import xdis


class CoObjectManager:

    def __init__ (self, co):
        self.co_list = []
        self.co_ea_map = {}
        self.walk_co_func(0, co)
        self.co_count = len(self.co_list)

    def walk_co_func(self, search_starts_ea, co_obj):
        f_ea = idaapi.find_bytes(co_obj.co_code, search_starts_ea)
        n_ea = f_ea + 1
        if f_ea != idaapi.BADADDR:
            size = len(co_obj.co_code)
            n_ea = f_ea + size
            obj = (co_obj, f_ea, n_ea - 1)
            self.co_list.append(obj)
            self.co_ea_map[f_ea] = obj

        for c in co_obj.co_consts:
            if xdis.disasm.iscode(c):
                self.walk_co_func(n_ea, c)
    def get_co_by_ea(self, ea):
        L, R = 0, self.co_count - 1
        while L <= R:
            M = (L + R) // 2
            co, min_ea, max_ea = self.co_list[M]
            if ea < min_ea:
                R = M - 1
            elif ea > max_ea:
                L = M + 1
            else:
                return co, min_ea, max_ea
        raise ValueError("No code object found")
