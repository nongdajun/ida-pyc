
# pyc file loader

import idaapi
import idc
import io

def accept_file(li, filename):
    if filename.lower().endswith('.pyc'):
        try:
            import xdis
            li.seek(0)
            """
            (
                tuple_version,
                timestamp,
                magic_int,
                co,
                is_pypy(magic_int, filename),
                source_size,
                sip_hash,
                
                is_graal,
                opcode,
            )
            """
            ret = xdis.load.load_module_from_file_object(li, filename, None, False, True)
            is_graal = ret[2] in xdis.magics.GRAAL3_MAGICS
            m_opcode = xdis.get_opcode(ret[0], ret[4])
            setattr(idaapi, 'pyc_info', ret + (is_graal, m_opcode))
        except Exception as ex:
            idaapi.warning(f"[WARN] Pyc loader failed to run: {ex}")
            return 0
        return {'format': "Python compiled bytecode", 'options': 1|0x8000}
    return 0

def load_file(li, neflags, format):

    li.seek(0)
    buf = li.read()

    buf_size = len(buf)

    if buf_size < 16:
        return 0

    setattr(idaapi, 'my_fmt_cmt', my_fmt_cmt)

    # Select the PC processor module
    idaapi.set_processor_type("Pyc", idc.SETPROC_LOADER_NON_FATAL)

    # TODO: make segments for stack, memory, storage

    # Copy the bytes
    idaapi.mem2base(buf, 0, buf_size)

    seg_magic = idaapi.segment_t()
    seg_magic.start_ea = 0
    seg_magic.end_ea = 4
    idaapi.add_segm_ex(seg_magic, ".magic", None, 0)

    h_out = io.StringIO()
    (
        tuple_version,
        timestamp,
        magic_int,
        co,
        is_pypy,
        source_size,
        sip_hash,
        is_graal,
        opcode
    ) = idaapi.pyc_info

    import xdis

    xdis.disasm.show_module_header(tuple_version,
                                   co,
                                   timestamp,
                                   h_out,
                                   is_pypy,
                                   magic_int,
                                   source_size,
                                   sip_hash,
                                   header=True,
                                   show_filename=True,
                                   is_graal=is_graal)

    idaapi.set_segment_cmt(seg_magic, f"{my_fmt_cmt(h_out.getvalue())}\nPress [Ctrl+F5] or [Alt+F5] to decompile...\n", 0)
    
    class DocstringViewer(idaapi.Form):
        """A form that displays a docstring."""

        def __init__(self, title, docstr):
            idaapi.Form.__init__(self,
                                      ("BUTTON YES NONE\n"
                                       "BUTTON NO NONE\n"
                                       "BUTTON CANCEL NONE\n"
                                       "%s\n\n"
                                       "<##Docstring##:{cbEditable}>"
                                       ) % title,
                                      {'cbEditable': idaapi.Form.MultiLineTextControl(text=docstr,
                                                                                           flags=idaapi.textctrl_info_t.TXTF_READONLY |
                                                                                                 idaapi.textctrl_info_t.TXTF_FIXEDFONT)})
    def _ctrl_f5_pressed():
        try:
            import uncompyle6
        except:
            idaapi.warning("<uncompyle6> is not installed!")
            return

        fn = idaapi.get_input_file_path()
        buf = io.StringIO()
        try:
            uncompyle6.decompile_file(fn, buf)
        except Exception as ex:
            idaapi.warning("<uncompyle6> failed: %s" % ex)
            return
        f = DocstringViewer("source: %s" % fn, buf.getvalue())
        f.modal = False
        f.openform_flags = idaapi.PluginForm.WOPN_TAB
        f, args = f.Compile()
        f.Open()

    idaapi.add_hotkey("Ctrl+F5", lambda :_ctrl_f5_pressed())
    idaapi.add_hotkey("Alt+F5", lambda :_ctrl_f5_pressed())

    return 1

def my_fmt_cmt(s):
    if s.startswith("# "):
        return "\n".join([i[2:] for i in s.split("\n")])
    return s