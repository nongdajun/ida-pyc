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
import idc
import ida_idp
import ida_auto
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
        if start_ea not in self.coManager.co_ea_map:
            return

        co = self.coManager.co_ea_map[start_ea][0]
        cmt = xdis.cross_dis.format_code_info(co, idaapi.pyc_info[0], is_graal=idaapi.pyc_info[7])
        idaapi.set_func_cmt(start_ea, idaapi.my_fmt_cmt(cmt), 0)

    def init_instructions(self):
        self.instruc = [] # why is there no T in this?

        m_opcode = idaapi.pyc_info[8]
        if not m_opcode:
            self.instruc.append({'name':"<ERROR>", 'feature':0})
            self.instruc_end = 1
            return -1

        self.instruc_hasoperand = [True if m_opcode.opname[i].startswith('<') else False for i in range(256)]
        for aname in dir(m_opcode):
            if not aname.startswith('has'):
                continue
            codes = getattr(m_opcode, aname)
            setattr(self, f'instruc_{aname}', tuple(i in codes for i in range(256)))
            for code in codes:
                self.instruc_hasoperand[code] = True
        self.instruc_hasoperand = tuple(self.instruc_hasoperand)

        for i in range(256):
            self.instruc.append({'name':f"<{i}>", 'feature':0})

        for (name, code) in m_opcode.opmap.items(): #_table.iteritems():
            features = 0 # initially zero

            if code in m_opcode.hasnargs: # has immediate
                features |= ida_idp.CF_USE1

            if name in ('INVALID', 'RETURN_VALUE'):
                features |= ida_idp.CF_STOP

            if code in m_opcode.hasjrel or code in m_opcode.hasjabs:
                features |= ida_idp.CF_JUMP
                if "BACKWARD" in name:
                    features |= ida_idp.CF_USE1  #backward jump
                if "_IF_" in name:
                    features |= ida_idp.CF_USE2  #condition jump

            if code in m_opcode.callop:
                features |= ida_idp.CF_CALL

            self.instruc[code] = {'name': name, 'feature':features}

            if name == 'RETURN_VALUE':
                self.icode_return = code

            if name == 'EXTENDED_ARG':
                self.icode_extend_arg = code

            if name == 'CALL_FUNCTION':
                self.icode_call_function = code

            if name == 'CALL_METHOD':
                self.icode_call_method = code

        self.instruc_end = len(self.instruc)

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
            idaapi.add_segm_ex(seg, 'co', None, idaapi.ADDSEG_NOAA)
            if i == 0:
                idaapi.add_entry(0, f_ea, "_start", False)
                #idaapi.add_func(f_ea)
            else:
                #idaapi.add_func(f_ea)
                idaapi.set_name(f_ea, fn)
            # Mark for analysis
            ida_auto.auto_make_proc(f_ea)

        idc.auto_wait()
        #print("*****************AUTO_DONE*********************")

    def get_current_co(self, addr):
        if addr < self.current_co_start_ea or addr > self.current_co_end_ea:
            co, self.current_co_start_ea, self.current_co_end_ea = self.coManager.get_co_by_ea(addr)
            self.current_co = co
            return co
        else:
            return self.current_co

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
