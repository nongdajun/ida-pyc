import idaapi
import idc
import ida_idp
import ida_xref
import ida_auto
import ida_ua
import ida_lines
import xdis
import pyc_base


class PycOldProcessor(pyc_base.PycProcessor):

    def notify_emu(self, insn):
        feature = insn.get_canon_feature()

        flows = (feature & ida_idp.CF_STOP) == 0

        #if feature & CF_JUMP:
        #    add_cref(insn.ea, insn.ea + 10, fl_JN)
        #elif feature & CF_CALL:
        #    add_cref(insn.ea, insn.ea + insn.size, fl_CN)

        if flows:
            ida_xref.add_cref(insn.ea, insn.ea + insn.size, ida_xref.fl_F)

        return 1

    def notify_out_operand(self, ctx, op):
        if op.specval == 0:
            return

        if self.last_extend_arg:
            op_value = op.value+self.last_extend_arg*256
            ctx.out_line(f"{op.value}({op_value})", ida_lines.COLOR_DSTR)
        else:
            op_value = op.value
            ctx.out_line(str(op_value), ida_lines.COLOR_DSTR)

        op_type = op.type

        if op_type != ida_ua.o_idpspec0:
            addr = op.addr
            if addr < self.current_co_start_ea or addr >self.current_co_end_ea:
                co, self.current_co_start_ea, self.current_co_end_ea = self.coManager.get_co_by_ea(addr)
                self.current_co = co
            else:
                co = self.current_co
            color = ida_lines.COLOR_MACRO
            if op_type == ida_ua.o_idpspec1:
                txt = f'({co.co_consts[op_value]})'
            elif op_type == ida_ua.o_idpspec2:
                txt = f'({co.co_names[op_value]})'
            elif op_type == ida_ua.o_idpspec3:
                txt = f'({co.co_varnames[op_value]})'
            else:
                color = ida_lines.COLOR_ERROR
                txt = '<UNKNOWN>'
            ctx.out_line(f"\t {txt}", color)

        return

    def notify_out_insn(self, ctx):
        ctx.out_mnemonic()
        #ctx.set_gen_cmt(False)
        ctx.out_one_operand(0)
        ctx.flush_outbuf()
        return

    def notify_ana(self, insn):
        #print(f"notify_ana: -> {insn.ea}")
        ea = insn.ea

        insn.size = 2
        itype = idaapi.get_byte(ea)

        # set the instruction
        insn.itype = itype

        op = insn[0]
        # custom type
        if self.instruc_hasconst[itype]:
            op.type = ida_ua.o_idpspec1
        elif self.instruc_hasname[itype]:
            op.type = ida_ua.o_idpspec2
        elif self.instruc_haslocal[itype]:
            op.type = ida_ua.o_idpspec3
        else:
            op.type = ida_ua.o_idpspec0
        op.dtype = ida_ua.dt_byte
        op_addr = ea + 1
        op.addr = op_addr  # operand is located after opcode
        op.value = idaapi.get_byte(op_addr)
        op.specval = 1 if self.instruc_hasoperand[itype] else 0

        if itype == self.icode_extend_arg:
            self.tmp_extend_arg = (self.tmp_extend_arg*256) + op.value
        else:
            self.last_extend_arg = self.tmp_extend_arg
            self.tmp_extend_arg = 0

        # return the instruction size here
        return 2

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
            #print(aname)
            codes = getattr(m_opcode, aname)
            setattr(self, f'instruc_{aname}', tuple(i in codes for i in range(256)))
            for code in codes:
                self.instruc_hasoperand[code] = True
        self.instruc_hasoperand = tuple(self.instruc_hasoperand)
        #print(self.instruc_hasoperand)

        for i in range(256):
            self.instruc.append({'name':f"<{i}>", 'feature':0})

        for (name, code) in m_opcode.opmap.items(): #_table.iteritems():
            features = 0 # initially zero

            if self.instruc_hasoperand[code]: # has immediate
                features |= ida_idp.CF_USE1

            if name == 'INVALID':
                features |= ida_idp.CF_STOP

            if code in m_opcode.hasjrel or code in m_opcode.hasjabs:
                features |= ida_idp.CF_JUMP

            if code in m_opcode.callop:
                features |= ida_idp.CF_CALL

            self.instruc[code] = {'name': name, 'feature':features}

            if name == 'RETURN_VALUE':
                self.icode_return = code

            if name == 'EXTENDED_ARG':
                self.icode_extend_arg = code
                self.tmp_extend_arg = 0
                self.last_extend_arg = 0

        self.instruc_end = len(self.instruc)


    def notify_newfile(self, filename):
        pyc_base.PycProcessor.notify_newfile(self, filename)


    def __init__(self):
        pyc_base.PycProcessor.__init__(self)


def PROCESSOR_ENTRY():
    return PycOldProcessor()