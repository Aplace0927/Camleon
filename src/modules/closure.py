import re

import idaapi
import ida_funcs
import ida_idp
import ida_kernwin
import ida_typeinf

OCAML_INT_ARG_REGS = [
    "rax",
    "rbx",
    "rsi",
    "rdi",
    "rdx",
    "rcx",
    "r8",
    "r9",
    "r12",
    "r13",
    "r10",
    "r11",
    "rbp",
]

OCAML_FLOAT_ARG_REGS = [
    "xmm0",
    "xmm1",
    "xmm2",
    "xmm3",
    "xmm4",
    "xmm5",
    "xmm6",
    "xmm7",
    "xmm8",
    "xmm9",
    "xmm10",
    "xmm11",
    "xmm12",
    "xmm13",
    "xmm14",
    "xmm15",
]


def _normalize_reg_list(regs):
    if regs is None:
        return None
    if isinstance(regs, str):
        tokens = re.split(r"[\s,]+", regs)
    else:
        tokens = regs
    result = []
    for token in tokens:
        if not token:
            continue
        cleaned = re.sub(r"[(){}]", "", token).strip().lower()
        if not cleaned or cleaned in {"and", "stack"}:
            continue
        result.append(cleaned)
    return result


def _reg_name_to_id(reg_name):
    if hasattr(ida_idp, "str2reg"):
        reg_id = ida_idp.str2reg(reg_name)
    else:
        reg_id = ida_idp.regname2reg(reg_name)
    if reg_id is None or reg_id < 0:
        return None
    return reg_id


def _is_float_arg(arg):
    arg_type = arg.type
    return arg_type.is_float() or arg_type.is_double()


def _apply_ocaml_cc_to_func(func, int_regs, float_regs):
    tinfo = ida_typeinf.tinfo_t()
    ftd = ida_typeinf.func_type_data_t()

    if hasattr(ida_funcs, "get_func_tinfo"):
        has_tinfo = ida_funcs.get_func_tinfo(tinfo, func)
    elif hasattr(ida_typeinf, "get_tinfo"):
        has_tinfo = ida_typeinf.get_tinfo(tinfo, func.start_ea)
    else:
        has_tinfo = idaapi.get_tinfo(tinfo, func.start_ea)

    has_details = has_tinfo and tinfo.get_func_details(ftd)
    if not has_details:
        ftd.cc = _get_usercall_cc()
        tinfo.create_func(ftd)
        return ida_typeinf.apply_tinfo(func.start_ea, tinfo, ida_typeinf.TINFO_DEFINITE)

    ftd.cc = _get_usercall_cc()

    int_index = 0
    float_index = 0
    if hasattr(ftd, "size"):
        arg_count = ftd.size()
    elif hasattr(ftd, "args"):
        arg_count = len(ftd.args)
    else:
        arg_count = 0

    for arg_index in range(arg_count):
        if hasattr(ftd, "__getitem__"):
            arg = ftd[arg_index]
        else:
            arg = ftd.args[arg_index]
        use_float = _is_float_arg(arg)
        regs = float_regs if use_float else int_regs
        reg_index = float_index if use_float else int_index

        if reg_index >= len(regs):
            if use_float:
                float_index += 1
            else:
                int_index += 1
            continue

        reg_id = _reg_name_to_id(regs[reg_index])
        if reg_id is None:
            if use_float:
                float_index += 1
            else:
                int_index += 1
            continue

        argloc = ida_typeinf.argloc_t()
        argloc.set_reg1(reg_id)
        arg.argloc = argloc
        if hasattr(ftd, "__setitem__"):
            ftd[arg_index] = arg
        else:
            ftd.args[arg_index] = arg

        if use_float:
            float_index += 1
        else:
            int_index += 1

    tinfo.create_func(ftd)
    return ida_typeinf.apply_tinfo(func.start_ea, tinfo, ida_typeinf.TINFO_DEFINITE)


def _get_usercall_cc():
    if hasattr(ida_typeinf, "CM_CC_USERCALL"):
        return ida_typeinf.CM_CC_USERCALL
    if hasattr(ida_typeinf, "CM_CC_SPECIAL"):
        return ida_typeinf.CM_CC_SPECIAL
    return ida_typeinf.CM_CC_UNKNOWN


def fix_calling_convention_all(int_regs=None, float_regs=None):
    int_regs = _normalize_reg_list(int_regs) or OCAML_INT_ARG_REGS
    float_regs = _normalize_reg_list(float_regs) or OCAML_FLOAT_ARG_REGS

    total = ida_funcs.get_func_qty()
    updated = 0
    for index in range(total):
        func = ida_funcs.getn_func(index)
        if not func:
            continue
        if _apply_ocaml_cc_to_func(func, int_regs, float_regs):
            updated += 1

    ida_kernwin.msg(
        "Camleon: applied OCaml calling convention to %d/%d functions\n"
        % (updated, total)
    )


def fix_calling_convention_current(int_regs=None, float_regs=None):
    int_regs = _normalize_reg_list(int_regs) or OCAML_INT_ARG_REGS
    float_regs = _normalize_reg_list(float_regs) or OCAML_FLOAT_ARG_REGS

    ea = ida_kernwin.get_screen_ea()
    func = ida_funcs.get_func(ea)
    if not func:
        ida_kernwin.msg("Camleon: no function at current address\n")
        return False

    updated = _apply_ocaml_cc_to_func(func, int_regs, float_regs)
    if updated:
        ida_kernwin.msg(
            "Camleon: applied OCaml calling convention to function at 0x%X\n"
            % func.start_ea
        )
    else:
        ida_kernwin.msg("Camleon: failed to apply calling convention\n")
    return updated


def fix_calling_convention(int_regs=None, float_regs=None):
    return fix_calling_convention_all(int_regs=int_regs, float_regs=float_regs)
