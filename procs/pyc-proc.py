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
        mnemonic = insn.get_canon_mnem()
        flows = (feature & CF_STOP) == 0
        if flows:
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
            ctx.out_line(f"{op.value} ({op.value+self.last_extend_arg*256})")
        else:
            ctx.out_line(str(op.value))
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
        op.type = o_idpspec0  # custom type
        op.dtype = dt_byte
        op_addr = ea + 1
        op.addr = op_addr  # operand is located after opcode
        op.value = idaapi.get_byte(op_addr)
        op.specval = 1 if self.instruc_has_operand[itype] else 0

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

        self.instruc_has_operand = [True if m_opcode.opname[i].startswith('<') else False for i in range(256)]
        for aname in dir(m_opcode):
            if not aname.startswith('has'):
                continue
            #print(aname)
            codes = getattr(m_opcode, aname)
            for code in codes:
                self.instruc_has_operand[code] = True
        #print(self.instruc_has_operand)

        for i in range(256):
            self.instruc.append({'name':f"<{i}>", 'feature':0})

        for (name, code) in m_opcode.opmap.items(): #_table.iteritems():
            features = 0 # initially zero

            if code in m_opcode.hasnargs: # has immediate
                features |= CF_USE1

            if name.startswith('JUMP_') or name in ('RETURN_VALUE', 'INVALID'):
                features |= CF_STOP

            if name.startswith('JUMP_'):
                features |= CF_JUMP

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



def PROCESSOR_ENTRY():
    return PycProcessor()
