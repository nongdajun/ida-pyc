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
