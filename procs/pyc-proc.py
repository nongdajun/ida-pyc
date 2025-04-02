import idc
import idaapi
from idc import *
from idaapi import *
import io


class PycProcessor(idaapi.processor_t):
    id = 0x8000 + 0x9977
    flag = PR_ADJSEGS | PRN_HEX | PR_ASSEMBLE
    cnbits = 8
    dnbits = 8
    psnames = ["pyc"]
    plnames = ["Pyc"]
    segreg_size = 0
    instruc_start = 0
    reg_names = ["SP"]
    assembler = {
        "header": [".magic"],
        "flag": AS_NCHRE | ASH_HEXF0 | ASD_DECF0 | ASO_OCTF0 | ASB_BINF0,
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

    def trace_sp(self, insn):
        pass

    def notify_emu(self, insn):
        feature = insn.get_canon_feature()
        #print "emulating", insn.get_canon_mnem(), hex(feature)
        #mnemonic = insn.get_canon_mnem()

        flows = (feature & CF_STOP) == 0

        #if feature & CF_JUMP:
        #    add_cref(insn.ea, insn.ea + 10, fl_JN)
        #elif feature & CF_CALL:
        #    add_cref(insn.ea, insn.ea + insn.size, fl_CN)
        if flows and (feature & CF_JUMP) == 0:
            add_cref(insn.ea, insn.ea + insn.size, fl_F)

        if may_trace_sp():
            if flows:
                self.trace_sp(insn)
            else:
                idc.recalc_spd(insn.ea)
        return 1

    def notify_func_bounds(self, code, func_ea, max_func_end_ea):
        """
        find_func_bounds() finished its work
        The module may fine tune the function bounds
        args:
          possible code - one of FIND_FUNC_XXX (check find_func_bounds)
          func_ea - func start ea
          max_func_end_ea (from the kernel's point of view)
        returns: possible_return_code
        """
        #print hex(func_ea), hex(max_func_end_ea), code
        #print print_insn_mnem(max_func_end_ea-1)
        #append_func_tail(func, jump_addr, BADADDR)
        #reanalyze_function(func)
        return FIND_FUNC_OK

    def notify_out_operand(self, ctx, op):
        if op.specval == 0:
            return

        if self.last_extend_arg:
            op_value = op.value+self.last_extend_arg*256
            ctx.out_line(f"{op.value}({op_value})", idaapi.COLOR_DSTR)
        else:
            op_value = op.value
            ctx.out_line(str(op_value), idaapi.COLOR_DSTR)

        op_type = op.type

        if op_type != o_idpspec0:
            addr = op.addr
            if addr < self.current_co_start_ea or addr >self.current_co_end_ea:
                co, self.current_co_start_ea, self.current_co_end_ea = idaapi.co_map[idaapi.get_segm_num(addr)]
                self.current_co = co
            else:
                co = self.current_co
            color = idaapi.COLOR_MACRO
            if op_type == o_idpspec1:
                txt = f'({co.co_consts[op_value]})'
            elif op_type == o_idpspec2:
                txt = f'({co.co_names[op_value]})'
            elif op_type == o_idpspec3:
                txt = f'({co.co_varnames[op_value]})'
            elif op_type == o_near:
                color = idaapi.COLOR_DEFAULT
                target_addr = op_value+1+addr
                idaapi.add_cref(addr-1, target_addr, idaapi.fl_JN)
                txt = idaapi.get_name(target_addr)
                if not txt:
                    txt = f'({hex(target_addr)})'
            elif op_type == o_far:
                color = idaapi.COLOR_DEFAULT
                target_addr = op_value+self.current_co_start_ea
                idaapi.add_cref(addr - 1, target_addr, idaapi.fl_JN)
                txt = idaapi.get_name(target_addr)
                if not txt:
                    txt = f'({hex(target_addr)})'
            else:
                color = idaapi.COLOR_ERROR
                txt = '<UNKNOWN>'
            ctx.out_line(f"\t {txt}", color)

        return

    def notify_out_insn(self, ctx):
        ctx.out_mnemonic()
        #if ctx.insn[0].type == o_idpspec0:
        #    ctx.out_char(" ")
        #    ctx.out_one_operand(0)
        #elif ctx.insn[0].type == o_near:
        #    ctx.out_char(" ")
        #    ctx.out_one_operand(0)
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
            op.type = o_idpspec1
        elif self.instruc_hasname[itype]:
            op.type = o_idpspec2
        elif self.instruc_haslocal[itype]:
            op.type = o_idpspec3
        elif self.instruc_hasjrel[itype]:
            op.type = o_near
        elif self.instruc_hasjabs[itype]:
            op.type = o_far
        else:
            op.type = o_idpspec0
        op.dtype = dt_byte
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

        m_opcode = getattr(idaapi,'pyc_opcode',None)
        if not getattr(idaapi,'pyc_opcode',None):
            self.instruc.append({'name':"X", 'feature':0})
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

            if code in m_opcode.hasnargs: # has immediate
                features |= CF_USE1

            if name == 'INVALID':
                features |= CF_STOP

            if name.startswith('JUMP_'):
                features |= CF_JUMP

            if name == "CALL" or name.startswith('CALL_'):
                features |= CF_CALL

            self.instruc[code] = {'name': name, 'feature':features}

            if name == 'RETURN_VALUE':
                self.icode_return = code

            if name == 'EXTENDED_ARG':
                self.icode_extend_arg = code
                self.tmp_extend_arg = 0
                self.last_extend_arg = 0

        self.instruc_end = len(self.instruc)

    def notify_assemble(self, ea, cs, ip, use32, line):
        idaapi.warning("Error trying to assemble '%s': not supported" % line)
        return None

    def __init__(self):
        processor_t.__init__(self)

        self.reg_names = ["SP", "vCS", "vDS"]
        self.reg_first_sreg = self.reg_names.index("vCS")
        self.reg_code_sreg = self.reg_names.index("vCS")

        self.reg_last_sreg =  self.reg_names.index("vDS")
        self.reg_data_sreg =  self.reg_names.index("vDS")

        self.init_instructions()

        self.has_rebuild_cf = False
        self.dst2src = {}

        self.current_co = None
        self.current_co_start_ea = 0
        self.current_co_end_ea = 0


def PROCESSOR_ENTRY():
    return PycProcessor()
