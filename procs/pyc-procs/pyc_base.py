import idaapi
import idc
import ida_idp
import ida_xref
import ida_auto
import ida_ua
import ida_lines
import xdis
from CoObjectManager import CoObjectManager


class PycProcessor(ida_idp.processor_t):
    id = 0x8000 + 0x9977
    flag = ida_idp.PR_NOCHANGE | ida_idp.PR_STACK_UP | ida_idp.PR_NO_SEGMOVE | ida_idp.PRN_HEX | ida_idp.PR_CNDINSNS
    cnbits = 8
    dnbits = 8
    psnames = ["pyc"]
    plnames = ["Pyc"]
    segreg_size = 0
    instruc_start = 0
    reg_names = ["SP"]
    assembler = {
        "header": [".magic"],
        "flag": ida_idp.AS_NCHRE | ida_idp.ASH_HEXF0 | ida_idp.ASD_DECF0 | ida_idp.ASO_OCTF0 | ida_idp.ASB_BINF0,
        "uflag": 0,
        "name": "python bytecode assembler",
        "origin": ".org",
        "end": ".end",
        "cmnt": "#",
        "ascsep": "'",
        "accsep": "'",
        "esccodes": "\"'",
        "a_ascii": ".ascii",
        "a_byte": ".byte",
        "a_word": ".word",
        "a_dword": ".dword",
        "a_bss": "dfs %s",
        "a_seg": "seg",
        "a_curip": "PC",
        "a_public": "",
        "a_weak": "",
        "a_extrn": ".extern",
        "a_comdef": "",
        "a_align": ".align",
        "lbrace": "(",
        "rbrace": ")",
        "a_sizeof_fmt": "size %s",
    }

    def notify_add_func(self, start_ea):
        # print(f"ADD FUNC @{hex(start_ea)}, {idaapi.get_name(start_ea)}")
        if start_ea not in self.coManager.co_ea_map:
            return

        co = self.coManager.co_ea_map[start_ea][0]
        cmt = xdis.cross_dis.format_code_info(co, idaapi.pyc_info[0], is_graal=idaapi.pyc_info[7])
        idaapi.set_func_cmt(start_ea, idaapi.my_fmt_cmt(cmt), 0)

    def init_instructions(self):
        raise NotImplementedError()

    def notify_newfile(self, filename):

        #idc.make_array(0, 4)
        idaapi.set_name(0, '_MAGIC_')

        print(f"Fetching all code objects in {filename} ...")

        self.coManager = CoObjectManager(idaapi.pyc_info[3])

        for i in range(self.coManager.co_count):
            co, f_ea, n_ea = self.coManager.co_list[i]
            fn = co.co_name.replace("<", "_").replace(">", "_")
            size = len(co.co_code)
            # Create the segment
            seg = idaapi.segment_t()
            seg.start_ea = f_ea
            seg.end_ea = f_ea + size
            idaapi.add_segm_ex(seg, 'co', "CODE", 0)
            if i == 0:
                idaapi.add_entry(0, f_ea, "_start", True)
                #idaapi.add_func(f_ea)
            else:
                #idaapi.add_func(f_ea)
                idaapi.set_name(f_ea, fn)
            # Mark for analysis
            ida_auto.auto_make_proc(f_ea)

    def __init__(self):
        ida_idp.processor_t.__init__(self)

        self.reg_names = ["SP", "vCS", "vDS"]
        self.reg_first_sreg = self.reg_names.index("vCS")
        self.reg_code_sreg = self.reg_names.index("vCS")

        self.reg_last_sreg =  self.reg_names.index("vDS")
        self.reg_data_sreg =  self.reg_names.index("vDS")

        self.init_instructions()

        self.coManager = None

        self.current_co = None
        self.current_co_start_ea = 0
        self.current_co_end_ea = 0
