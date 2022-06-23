import idaapi
import pyperclip as pc
from idc import *
from ida_hexrays import *
from ida_kernwin import *

_ver = '1.0.0'
_call = '__fastcall'

#------------------------------------------------------------------------------
# IDA Plugin Stub
#------------------------------------------------------------------------------

def PLUGIN_ENTRY():
    return BdsDevHelper()

class BdsDevHelper(ida_idaapi.plugin_t):

    flags = ida_idaapi.PLUGIN_UNL
    comment = "The bedrock dedicated server development helper, by: redbeanw."
    help = ""
    wanted_name = "BDSDevHelper"
    wanted_hotkey = ""

    def init(self):
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        pass

class Hooks(idaapi.UI_Hooks):

    def populating_widget_popup(self, widget, popup, ctx):
        
        if ida_kernwin.get_widget_type(widget) != ida_kernwin.BWN_DISASM:
            return

        ida_kernwin.attach_action_to_popup(widget, popup, asTInstanceHook.NAME, "Add breakpoint", ida_kernwin.SETMENU_APP)
        ida_kernwin.attach_action_to_popup(widget, popup, asTClasslessInstanceHook.NAME, "Add breakpoint", ida_kernwin.SETMENU_APP)
        ida_kernwin.attach_action_to_popup(widget, popup, asSymCall.NAME, "Add breakpoint", ida_kernwin.SETMENU_APP)
        ida_kernwin.attach_action_to_popup(widget, popup, asTHook.NAME, "Add breakpoint", ida_kernwin.SETMENU_APP)
        ida_kernwin.attach_action_to_popup(widget, popup, "-",  asTHook.TEXT, ida_kernwin.SETMENU_INS)

    def ready_to_run(self, *args):
        for action in PLUGIN_ACTIONS:
            desc = ida_kernwin.action_desc_t(
                action.NAME,
                action.TEXT,
                action(self),
                '',
                action.TOOLTIP,
                -1
            )
            if not ida_kernwin.register_action(desc):
                print("[x] Register action '%s' failed!" % action.NAME)
        print('[*] BDS Dev Helper is loaded, ver %s.' % _ver)
        print('[*] By: RedbeanW.')

hooks = Hooks()
hooks.hook()

def fixIdaBugAndGetArguments(func):
    m = func.argidx
    n = func.arguments
    if m[0] == 1:
        n[0],n[1] = n[1],n[0]
    return n

def cleanType(name,NoPointer = False):
    rtn = str()
    for t in name.split(' '):
        if t != 'const' and t != 'struct' and t != 'class':
            rtn = rtn + t + ' '
    if NoPointer:
        rtn = rtn.replace('*','')
    return rtn.strip()
            

#------------------------------------------------------------------------------
# Registered Actions
#------------------------------------------------------------------------------

class asTHook(ida_kernwin.action_handler_t):
    NAME = 'helper:THook'
    TEXT = "Copy as THook"
    TOOLTIP = "Generate the THook macro for this function."

    TEMPLATE = "THook({return_type}, \"{symbol}\"{format_if_args}{call_args})\n{{\n    {return_if_not_void}original({return_args});\n}}"

    def __init__(self, core):
        ida_kernwin.action_handler_t.__init__(self)
        self.core = core

    def activate(self, ctx):
        ea = here()
        if ea == idaapi.BADADDR:
            print('[x] cannot get here ea.')
            return

        # get function.
        symbol = get_name(ea)
        if not symbol or symbol == '':
            print('[x] cannot get symbol.')
            return
        func_data = decompile(ea)
        func_detail = str(func_data.type)
        return_type = cleanType(func_detail[0:func_detail.find(_call)])
        call_args = str()
        return_args = str()
        FirstArg = True
        for i in fixIdaBugAndGetArguments(func_data):
            if FirstArg and i.name == 'this':
                arg_name = 'self'
            else:
                arg_name = i.name
            call_args = call_args + cleanType(str(i.tif)) + ' ' + arg_name + ', '
            return_args = return_args + arg_name + ', '
        call_args = call_args[0:len(call_args)-2]
        return_args = return_args[0:len(return_args)-2]

        # handles.
        if call_args != '':
            format_if_args = ', \n    '
        else:
            format_if_args = ''
        if return_type != 'void':
            return_if_not_void = 'return '
        else:
            return_if_not_void = ''
        
        # format.
        generated = self.TEMPLATE.format(
            return_type = return_type,
            symbol = symbol,
            format_if_args = format_if_args,
            call_args = call_args,
            return_if_not_void = return_if_not_void,
            return_args = return_args
        )

        pc.copy(generated)
        print('[+] THook here is copid.')
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class asTInstanceHook(ida_kernwin.action_handler_t):
    NAME = 'helper:TInstanceHook'
    TEXT = "Copy as TInstanceHook"
    TOOLTIP = "Generate the TInstanceHook macro for this function."

    TEMPLATE = "TInstanceHook({return_type}, \"{symbol}\", \n    {this_pointer_type}{format_if_args_short}{call_args})\n{{\n    {return_if_not_void}original(this{format_if_args_short}{return_args});\n}}"

    def __init__(self, core):
        ida_kernwin.action_handler_t.__init__(self)
        self.core = core

    def activate(self, ctx):
        ea = here()
        if ea == idaapi.BADADDR:
            print('[x] cannot get here ea.')
            return

        # get function.
        symbol = get_name(ea)
        if not symbol or symbol == '':
            print('[x] cannot get symbol.')
            return
        func_data = decompile(ea)
        func_detail = str(func_data.type)
        return_type = cleanType(func_detail[0:func_detail.find(_call)])
        call_args = str()
        return_args = str()
        FirstArg = True
        for i in fixIdaBugAndGetArguments(func_data):
            if FirstArg:
                this_pointer_type = cleanType(str(i.tif),True)
                FirstArg = False
            else:
                call_args = call_args + cleanType(str(i.tif)) + ' ' + i.name + ', '
                return_args = return_args + i.name + ', '
        call_args = call_args[0:len(call_args)-2]
        return_args = return_args[0:len(return_args)-2]

        # handles.
        if call_args != '':
            format_if_args_short = ', '
        else:
            format_if_args_short = ''
        if return_type != 'void':
            return_if_not_void = 'return '
        else:
            return_if_not_void = ''
        
        # format.
        generated = self.TEMPLATE.format(
            return_type = return_type,
            symbol = symbol,
            this_pointer_type = this_pointer_type,
            format_if_args_short = format_if_args_short,
            call_args = call_args,
            return_if_not_void = return_if_not_void,
            return_args = return_args
        )

        pc.copy(generated)
        print('[+] TInstanceHook here is copid.')
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class asTClasslessInstanceHook(ida_kernwin.action_handler_t):
    NAME = 'helper:TClasslessInstanceHook'
    TEXT = "Copy as TClasslessInstanceHook"
    TOOLTIP = "Generate the TClasslessInstanceHook macro for this function."

    TEMPLATE = "TClasslessInstanceHook({return_type}, \"{symbol}\"{format_if_args}{call_args})\n{{\n    {return_if_not_void}original(this{format_if_args_short}{return_args});\n}}"

    def __init__(self, core):
        ida_kernwin.action_handler_t.__init__(self)
        self.core = core

    def activate(self, ctx):
        ea = here()
        if ea == idaapi.BADADDR:
            print('[x] cannot get here ea.')
            return

        # get function.
        symbol = get_name(ea)
        if not symbol or symbol == '':
            print('[x] cannot get symbol.')
            return
        func_data = decompile(ea)
        func_detail = str(func_data.type)
        return_type = cleanType(func_detail[0:func_detail.find(_call)])
        call_args = str()
        return_args = str()
        FirstArg = True
        for i in fixIdaBugAndGetArguments(func_data):
            if FirstArg:
                FirstArg = False
                continue
            call_args = call_args + cleanType(str(i.tif)) + ' ' + i.name + ', '
            return_args = return_args + i.name + ', '
        call_args = call_args[0:len(call_args)-2]
        return_args = return_args[0:len(return_args)-2]

        # handles.
        if call_args != '':
            format_if_args = ', \n    '
            format_if_args_short = ', '
        else:
            format_if_args = ''
            format_if_args_short = ''
        if return_type != 'void':
            return_if_not_void = 'return '
        else:
            return_if_not_void = ''
        
        # format.
        generated = self.TEMPLATE.format(
            return_type = return_type,
            symbol = symbol,
            format_if_args = format_if_args,
            format_if_args_short = format_if_args_short,
            call_args = call_args,
            return_if_not_void = return_if_not_void,
            return_args = return_args
        )

        pc.copy(generated)
        print('[+] TClasslessInstanceHook here is copid.')
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_IDB

class asSymCall(ida_kernwin.action_handler_t):
    NAME = 'helper:SymCall'
    TEXT = "Copy as SymCall"
    TOOLTIP = "Use SymCall to call this function."

    TEMPLATE = "SymCall(\"{symbol}\",\n    {return_type}{format_if_args_short}{call_types}){need_if_args};"

    def __init__(self, core):
        ida_kernwin.action_handler_t.__init__(self)
        self.core = core

    def activate(self, ctx):
        ea = here()
        if ea == idaapi.BADADDR:
            print('[x] cannot get here ea.')
            return

        # get function.
        symbol = get_name(ea)
        if not symbol or symbol == '':
            print('[x] cannot get symbol.')
            return
        func_data = decompile(ea)
        func_detail = str(func_data.type)
        return_type = cleanType(func_detail[0:func_detail.find(_call)])
        call_types = str()
        for i in fixIdaBugAndGetArguments(func_data):
            call_types = call_types + cleanType(str(i.tif)) + ', '
        call_types = call_types[0:len(call_types)-2]

        # handles.
        if call_types != '':
            format_if_args_short = ', '
            need_if_args = '()'
        else:
            format_if_args_short = ''
            need_if_args = ''
        
        # format.
        generated = self.TEMPLATE.format(
            return_type = return_type,
            symbol = symbol,
            format_if_args_short = format_if_args_short,
            need_if_args = need_if_args,
            call_types = call_types
        )

        pc.copy(generated)
        print('[+] SymCall here is copid.')
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

PLUGIN_ACTIONS = \
[
    asTHook,
    asTInstanceHook,
    asTClasslessInstanceHook,
    asSymCall
]