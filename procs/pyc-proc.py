import idaapi
import idc
import ida_idp
import ida_xref
import ida_auto
import ida_ua
import ida_lines


try:
    import xdis
except:
    idaapi.warning("<xdis> python module is not installed!")


class CodeObjectManager:

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


class PycProcessor(ida_idp.processor_t):
    id = 0x8000 + 0x9977
    flag = ida_idp.PR_NOCHANGE | ida_idp.PR_STACK_UP | ida_idp.PR_NO_SEGMOVE | ida_idp.PRN_DEC | ida_idp.PR_CNDINSNS
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

    def trace_sp(self, insn):
        pass

    def notify_add_func(self, start_ea):
        # print(f"ADD FUNC @{hex(start_ea)}, {idaapi.get_name(start_ea)}")
        if start_ea not in self.co_map:
            return

        co = self.coManager.co_ea_map[start_ea][0]
        is_graal = idaapi.pyc_info[2] in xdis.magics.GRAAL3_MAGICS
        cmt = xdis.cross_dis.format_code_info(co, idaapi.pyc_info[0], is_graal=is_graal)
        idaapi.set_func_cmt(start_ea, fmt_cmt(cmt), 0)

    def notify_emu(self, insn):
        feature = insn.get_canon_feature()

        flows = (feature & ida_idp.CF_STOP) == 0

        #if feature & CF_JUMP:
        #    add_cref(insn.ea, insn.ea + 10, fl_JN)
        #elif feature & CF_CALL:
        #    add_cref(insn.ea, insn.ea + insn.size, fl_CN)

        if flows and (feature & ida_idp.CF_JUMP) == 0:
            ida_xref.add_cref(insn.ea, insn.ea + insn.size, ida_xref.fl_F)

        if ida_auto.may_trace_sp():
            if flows:
                self.trace_sp(insn)
            else:
                idc.recalc_spd(insn.ea)
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
            elif op_type == ida_ua.o_near:
                color = ida_lines.COLOR_DEFAULT
                target_addr = op_value+1+addr
                idaapi.add_cref(addr-1, target_addr, ida_xref.fl_JN)
                txt = idaapi.get_name(target_addr)
                if not txt:
                    txt = f'({hex(target_addr)})'
                ctx.out_addr_tag(target_addr)
            elif op_type == ida_ua.o_far:
                color = ida_lines.COLOR_DEFAULT
                target_addr = op_value+self.current_co_start_ea
                idaapi.add_cref(addr - 1, target_addr, ida_xref.fl_JN)
                txt = idaapi.get_name(target_addr)
                if not txt:
                    txt = f'({hex(target_addr)})'
                ctx.out_addr_tag(target_addr)
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
        elif self.instruc_hasjrel[itype]:
            op.type = ida_ua.o_near
        elif self.instruc_hasjabs[itype]:
            op.type = ida_ua.o_far
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

        m_opcode = getattr(idaapi,'pyc_opcode',None)
        if not getattr(idaapi,'pyc_opcode',None):
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

            if code in m_opcode.hasnargs: # has immediate
                features |= ida_idp.CF_USE1

            if name in ('INVALID', 'RETURN_VALUE'):
                features |= ida_idp.CF_STOP

            if name.startswith('JUMP_'):
                features |= ida_idp.CF_JUMP

            if name == "CALL" or name.startswith('CALL_'):
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

        idc.make_array(0, 4)
        idaapi.set_name(0, '_MAGIC_')

        print(f"Fetching all code objects in {filename} ...")

        self.coManager = CodeObjectManager(idaapi.pyc_info[3])

        for i in range(self.coManager.co_count):
            co, f_ea, n_ea = self.coManager.co_list[i]
            fn = co.co_name.replace("<", "_").replace(">", "_")
            '''
            # Create the segment
            seg = idaapi.segment_t()
            seg.start_ea = f_ea
            seg.end_ea = f_ea + size
            idaapi.add_segm_ex(seg, '', "CODE", 0)
            '''
            if i == 0:
                idaapi.add_entry(0, f_ea, "_start", False)
                # idaapi.add_func(f_ea)
            else:
                # idaapi.add_func(f_ea, n_ea)
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

        self.has_rebuild_cf = False
        self.dst2src = {}

        self.coManager = None

        self.current_co = None
        self.current_co_start_ea = 0
        self.current_co_end_ea = 0


def fmt_cmt(s):
    if s.startswith("# "):
        return "\n".join([i[2:] for i in s.split("\n")])
    return s


def PROCESSOR_ENTRY():
    return PycProcessor()

