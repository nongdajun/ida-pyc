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

import ida_kernwin
import idc
import ida_ua
import idaapi



def Pyc_do_patch():
    ea = ida_kernwin.get_screen_ea()
    if ea == idc.BADADDR:
        return

    # print(f"view_dblclick->{ea}")

    form_type = ida_kernwin.get_widget_type(ida_kernwin.get_current_widget())
    if form_type != ida_kernwin.BWN_DISASM:
        return

    insn = idaapi.insn_t()
    if ida_ua.decode_insn(insn, ea) != 2:
        return

    insn_name = insn.get_canon_mnem()
    op = insn[0]
    if op.specval:
        init_str = f"{insn_name} {op.value % 256}"
    else:
        init_str = insn_name

    def try_parse_byte(s):
        try:
            if s.startswith("0x") or s.startswith("0X"):
                n = int(s, 16)
            else:
                n = int(s)
                if 0 <= n <= 255:
                    return n
        except:
            return None

    m_opcode = idaapi.pyc_info[8]

    inp_str = init_str
    while True:
        inp_str = ida_kernwin.ask_str(inp_str, 9696, 'Patch as')
        if not inp_str:
            return

        inp_arr = inp_str.strip().split(" ")
        inp_arr_len = len(inp_arr)

        if inp_arr_len > 2:
            ida_kernwin.warning("Invalid input!")
            continue

        if inp_arr[0] in m_opcode.opmap:
            b1 = m_opcode.opmap[inp_arr[0].upper()]
        else:
            b1 = try_parse_byte(inp_arr[0])
            if b1 is None:
                ida_kernwin.warning("Invalid opcode!")
                continue

        if inp_arr_len == 2:
            b2 = try_parse_byte(inp_arr[1])
            if b2 is None:
                ida_kernwin.warning("Invalid oprand value!")
                continue
            idaapi.patch_bytes(ea, bytes([b1, b2]))
            break
        else:
            idaapi.patch_byte(ea, b1)
            break
    ida_kernwin.refresh_idaview_anyway()


def Pyc_do_change_opcode(opcode):
    ea = ida_kernwin.get_screen_ea()
    if ea == idc.BADADDR:
        return
    idaapi.patch_byte(ea, opcode)
    ida_kernwin.refresh_idaview_anyway()


APPLY_PATCH_OUTPUT_FILE = None

def Pyc_apple_patches():
    global APPLY_PATCH_OUTPUT_FILE
    if not APPLY_PATCH_OUTPUT_FILE:
        APPLY_PATCH_OUTPUT_FILE = f"{idaapi.get_input_file_path()}.patched.pyc"
    ret = ida_kernwin.ask_file(True, APPLY_PATCH_OUTPUT_FILE, ".pyc")
    if not ret:
        return
    with open(idaapi.get_input_file_path(), "rb") as rf:
        buf = bytearray(rf.read())
        def visit_patched_bytes(ea, fpos, org_val, patch_val):
            buf[ea] = patch_val
        if idaapi.visit_patched_bytes(0, 0, visit_patched_bytes) == 0:
            with open(ret, "wb") as wf:
                wf.write(buf)
                APPLY_PATCH_OUTPUT_FILE = ret
                ida_kernwin.info("Apply patches success!")


#IDA View Hooks
class Pyc_View_Hooks(ida_kernwin.View_Hooks):

    def __init__(self):
        ida_kernwin.View_Hooks.__init__(self)

    #def view_dblclick(self, view, ev):
    #    if ev.button & ida_kernwin.VME_RIGHT_BUTTON:
    #        Pyc_do_patch()


class Pyc_UI_Hooks(ida_kernwin.UI_Hooks):

    def __init__(self):
        ida_kernwin.UI_Hooks.__init__(self)
        self.current_highlight_at = None
        self.current_highlight_targets = []

    def finish_populating_widget_popup(self, widget, popup):
        w_type = ida_kernwin.get_widget_type(widget)
        if w_type != ida_kernwin.BWN_DISASM:
            return
        idaapi.attach_action_to_popup(widget, popup, 'patch_menu_cust', None, idaapi.SETMENU_ENSURE_SEP)

        global pyc_change_op_actions
        for a, d in pyc_change_op_actions:
            idaapi.attach_action_to_popup(widget, popup, a, f"* Change selected opercode/ {d}... /")

        idaapi.attach_action_to_popup(widget, popup, 'PatchedBytes', "* Patch pyc file/")
        idaapi.attach_action_to_popup(widget, popup, 'patch_menu_apply_patches', "* Patch pyc file/")


    def screen_ea_changed(self, ea, prev_ea):

        if self.current_highlight_at == ea:
            return

        w_type = ida_kernwin.get_widget_type(ida_kernwin.get_current_widget())
        if w_type != ida_kernwin.BWN_DISASM:
            return

        #print(f"screen_ea_changed->{hex(ea)}")

        if self.current_highlight_targets:
            for target, old_color in self.current_highlight_targets:
                idc.set_color(target, idc.CIC_ITEM, old_color)

        self.current_highlight_targets.clear()

        if ea == idc.BADADDR:
            return

        insn = idaapi.insn_t()
        if ida_ua.decode_insn(insn, ea) != 2:
            return

        op = insn[0]

        if op.specflag4:  # CALLS
            insn_name = insn.get_canon_mnem()
            if insn_name == 'CALL_FUNCTION':
                target = op.addr - 3 - (op.value * 2)
                self.current_highlight_targets.append((target, idc.get_color(target, idc.CIC_ITEM)))
                idc.set_color(target, idc.CIC_ITEM, 0xffeedd)
            elif insn_name == 'CALL_METHOD':
                target = op.addr - 3 - (op.value * 2)
                self.current_highlight_targets.append((target-2, idc.get_color(target-2, idc.CIC_ITEM)))
                self.current_highlight_targets.append((target, idc.get_color(target, idc.CIC_ITEM)))
                idc.set_color(target - 2, idc.CIC_ITEM, 0xffddcc)
                idc.set_color(target, idc.CIC_ITEM, 0xffeedd)


def Pyc_Commnent_Handler(is_repeatable):
    form_type = ida_kernwin.get_widget_type(ida_kernwin.get_current_widget())
    if form_type != ida_kernwin.BWN_DISASM:
        return
    ea = ida_kernwin.get_screen_ea()
    if ea == idc.BADADDR:
        return
    if is_repeatable:
        ret = idaapi.ask_text(1024, idc.get_cmt(ea, is_repeatable), 'Enter repeatable comment:')
    else:
        ret = idaapi.ask_text(1024, idc.get_cmt(ea, is_repeatable), 'Enter comment:')
    if ret is None:
        return
    idc.set_cmt(ea, ret, is_repeatable)


pyc_view_hooks = Pyc_View_Hooks()
pyc_ui_hooks = Pyc_UI_Hooks()

pyc_change_op_actions = []

def init():
    pyc_info = idaapi.pyc_info
    tuple_version, is_pypy = pyc_info[0], pyc_info[4]
    ret = pyc_view_hooks.hook() and pyc_ui_hooks.hook()
    if tuple_version[0] == 3:
        ret = ret and pyc_ui_hooks.hook()
    if not ret:
        ida_kernwin.warning(f"ida-pyc ui init failed!")
    ida_kernwin.add_hotkey(";", lambda: Pyc_Commnent_Handler(True))
    ida_kernwin.add_hotkey(":", lambda: Pyc_Commnent_Handler(False))
    ida_kernwin.add_hotkey("e", lambda: Pyc_do_patch())

    ah = idaapi.action_handler_t()
    ah.update = lambda o: idaapi.AST_ENABLE_ALWAYS
    ah.activate = lambda o: Pyc_do_patch()
    idaapi.register_action(idaapi.action_desc_t("patch_menu_cust", "* Patch selected bytecode...", ah, None, None, 0))

    ah = idaapi.action_handler_t()
    ah.update = lambda o: idaapi.AST_ENABLE_ALWAYS
    ah.activate = lambda o: Pyc_apple_patches()
    idaapi.register_action(idaapi.action_desc_t("patch_menu_apply_patches", "Apply patches (save new file) ...", ah, None, None, 0))

    idaapi.attach_action_to_menu(f"Edit/Patch program/", 'patch_menu_apply_patches', idaapi.SETMENU_ENSURE_SEP)
    ida_kernwin.update_action_visibility('ApplyPatches', False)

    class change_opercode_handler(idaapi.action_handler_t):

        def __init__(self, opcode):
            idaapi.action_handler_t.__init__(self)
            self.opcode = opcode

        def activate(self, ctx):
            Pyc_do_change_opcode(self.opcode)
            return True

        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS

    global pyc_change_op_actions
    m_opcode = idaapi.pyc_info[8]
    keys = sorted(m_opcode.opmap.keys())
    for k in keys:
        m_name = f"patch_menu_chg_{k}"
        opcode = m_opcode.opmap[k]
        ah = change_opercode_handler(opcode)
        idaapi.register_action(idaapi.action_desc_t(m_name, f"{k} ={opcode}", ah, None, None, 0))
        pyc_change_op_actions.append((m_name, k[:1]))


