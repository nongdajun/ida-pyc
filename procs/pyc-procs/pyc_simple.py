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
import ida_idp
import ida_xref
import ida_ua
import ida_lines
import pyc_base


class PycSimpleProcessor(pyc_base.PycProcessor):

    def notify_emu(self, insn):
        ###print(f"notify_emu={ea}")
        feature = insn.get_canon_feature()
        ea = insn.ea

        flows = (feature & ida_idp.CF_STOP) == 0

        if flows:
            ida_xref.add_cref(ea, ea + 2, ida_xref.fl_F)

        return 1

    def notify_out_operand(self, ctx, op):
        if op.specval == 0:
            ctx.out_line(str(op.value).rjust(3, ' '), ida_lines.COLOR_HIDNAME)
            return

        op_value = op.value

        if op.specflag1:
            ctx.out_line(str(op.specflag2).rjust(3, ' '), ida_lines.COLOR_DSTR)
            ctx.out_line(f"({op_value})", ida_lines.COLOR_STRING)

        else:
            ctx.out_line(str(op_value).rjust(3, ' '), ida_lines.COLOR_DSTR)

        op_type = op.type
        addr = op.addr

        if self.instruc_hasconst[op_type]:
            map_attr_name = "co_consts"
        elif self.instruc_hasname[op_type]:
            map_attr_name = "co_names"
        elif self.instruc_haslocal[op_type]:
            map_attr_name = "co_varnames"
        else:
            map_attr_name = None

        if map_attr_name:
            co = self.get_current_co(addr)
            ctx.out_line(f"   ({getattr(co, map_attr_name)[op_value]})", ida_lines.COLOR_MACRO)

        return

    def notify_out_insn(self, ctx):
        #ctx.set_gen_cmt(False)
        ctx.out_mnem(18)
        ctx.out_one_operand(0)
        ctx.flush_outbuf()
        return

    def notify_ana(self, insn):
        ## print(f"notify_ana: -> {insn.ea}")
        ea = insn.ea

        insn.size = 2

        itype = idaapi.get_byte(ea)

        # set the instruction
        insn.itype = itype

        op = insn[0]
        op.type = itype
        op.dtype = ida_ua.dt_byte
        op_addr = ea + 1
        op.addr = op_addr  # operand is located after opcode
        op.value = idaapi.get_byte(op_addr)

        if self.instruc_hasoperand[itype]:
            op.specval = 1
            feature = insn.get_canon_feature()
            # EXTENDED_ARG
            if idaapi.get_byte(ea - 2) == self.icode_extend_arg:
                op.specflag1 = 1
                ext_value = op.value + idaapi.get_byte(ea - 1) * 256
                if idaapi.get_byte(ea - 4) == self.icode_extend_arg:
                    ext_value += idaapi.get_byte(ea - 3) * 65536
                    if idaapi.get_byte(ea - 6) == self.icode_extend_arg:
                        ext_value += idaapi.get_byte(ea - 5) * 16777216
                op.specflag2 = op.value
                op.value = ext_value
            else:
                op.specflag1 = 0
            op.specflag3 = 1 if feature & ida_idp.CF_USE1 else 0
        else:
            op.specval = 0

        # return the instruction size here
        return 2

    def init_instructions(self):
        pyc_base.PycProcessor.init_instructions(self)

    def notify_newfile(self, filename):
        pyc_base.PycProcessor.notify_newfile(self, filename)


    def __init__(self):
        pyc_base.PycProcessor.__init__(self)


def PROCESSOR_ENTRY():
    return PycSimpleProcessor()