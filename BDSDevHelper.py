import idaapi
import idautils
import ida_nalt
import pyperclip as pc
from idc import *
from ida_hexrays import *
from ida_kernwin import *
import tkinter.filedialog as askFile
import tkinter.messagebox as msgBox
import json
import os

_ver = '1.2.0'
_call = '__fastcall'

#------------------------------------------------------------------------------
# IDA Plugin Stub
#------------------------------------------------------------------------------

def PLUGIN_ENTRY():
    return BDSDevHelper()

class BDSDevHelper(ida_idaapi.plugin_t):

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
        
        # ida_kernwin.attach_action_to_menu("Edit/BDSDevHelper/Load original data", loadOriginalData.NAME, ida_kernwin.SETMENU_INS)
        ida_kernwin.attach_action_to_menu("Edit/BDSDevHelper/Export TIL information", export.NAME, ida_kernwin.SETMENU_INS)
        
        print('[*] BDS Dev Helper is loaded, ver %s.' % _ver)
        print('[*] By: RedbeanW.')

hooks = Hooks()
hooks.hook()

#------------------------------------------------------------------------------
# Utils
#------------------------------------------------------------------------------

class Utils():

    @staticmethod
    def fixIdaBugAndGetArguments(func):
        m = func.argidx
        n = func.arguments
        if m[0] == 1:
            n[0],n[1] = n[1],n[0]
        return n

    @staticmethod
    def cleanType(name,NoPointer = False):
        rtn = str()
        for t in name.split(' '):
            if t != 'const' and t != 'struct' and t != 'class':
                rtn = rtn + t + ' '
        if NoPointer:
            rtn = rtn.replace('*','')
        return rtn.strip()

    @staticmethod
    def changeVariableType(ea, lvar, tpe):
        lsi = lvar_saved_info_t()
        lsi.ll = lvar
        lsi.type = tpe
        return modify_user_lvar_info(ea, MLI_TYPE, lsi)

    @staticmethod
    def getMemberType(sid, offset):
        struct = ida_struct.get_struc(sid)
        member = ida_struct.get_member(struct, offset)
        tif = ida_typeinf.tinfo_t()
        if ida_struct.get_member_tinfo(tif, member):
            return tif.__str__() 
        return ""    

#------------------------------------------------------------------------------
# Registered Actions
#------------------------------------------------------------------------------

class export(ida_kernwin.action_handler_t):

    NAME = "helper:export"
    TEXT = "Export all TIL information."
    TOOLTIP = "Export all structure&enums&types information from idb."

    def __init__(self, core):
        ida_kernwin.action_handler_t.__init__(self)
        self.core = core
    
    def activate(self, ctx):

        # ask file name
        file_name = askFile.asksaveasfilename(
            title = 'Where to save structure data?',
            filetypes = [('Json File','*.json'),('All files','*')],
            initialdir = os.getcwd()
            )
        if file_name[len(file_name)-5:] != '.json':
            file_name = file_name + '.json'
        
        # global data
        j = {
            'structure': list(),
            'enums': list()
        }
        banned_prefix = [
            '_',
            '$',
            'baseclass_',
            'vn_',
            'vna_',
            'gap',
            'st_',
            'std::',
            'entt::',
            'Elf',
            'gsl::',
            'grpc::',
            'boost::',
            'JsonUtil::JsonSchema',
            'JsonUtil::JsonParseState'
        ]
        temp_added = dict()
        print('[!] Initialization, %d prefixes will be skipped.' % len(banned_prefix))

        # get structure information.
        for idx,sid,struct in idautils.Structs():
            struct = str(struct)
            try:
                for word in banned_prefix:
                    if struct[:len(word)] == word:
                        raise -1
            except:
                continue
            members = []
            for offset,mem,size in idautils.StructMembers(sid):
                mem = str(mem)
                members.append({
                    'name': mem,
                    'type': Utils.getMemberType(sid,offset),
                    'offset': offset,
                    'size': size
                })
            temp_added[struct] = 1
            j['structure'].append({
                    'struct_name': struct,
                    'members': members
                })
        print('[+] %d structures are exported.' % len(j['structure']))
        
        # get enum information.
        for i in range(ida_enum.get_enum_qty()):
            enum = ida_enum.getn_enum(i)
            name = ida_enum.get_enum_name(enum)
            try:
                for word in banned_prefix:
                    if name[:len(word)] == word:
                        raise -1
            except:
                continue
            members = list()

            class visitor(ida_enum.enum_member_visitor_t):
                def visit_enum_member(self, cid, value):
                    members.append({
                        'name': ida_enum.get_enum_member_name(cid),
                        'value': value,
                    })
                    return 0

            ida_enum.for_all_enum_members(enum, visitor())
            j['enums'].append({
                'enum_name': name,
                'members': members,
            })
            temp_added[name] = 1
        print('[+] %d enums are exported.' % len(j['enums']))

        # get local type information(supplement)
        til = ida_typeinf.get_idati()
        count = 0
        for ordinal in range(ida_typeinf.get_ordinal_qty(til)):
            tinfo = ida_typeinf.tinfo_t()
            if tinfo.get_numbered_type(til, ordinal):
                typen = str(tinfo)
                clss = str()
                clss2 = str()
                try:
                    if tinfo.is_enum():
                        clss = 'enums'
                        clss2 = 'enum_name'
                    elif tinfo.is_struct():
                        clss = 'structure'
                        clss2 = 'struct_name'
                    else:
                        raise -3
                    if typen in temp_added:
                        raise -1
                    for word in banned_prefix:
                        if typen[:len(word)] == word:
                            raise -2
                except:
                    continue                
                j[clss].append({
                    '%s'%clss2: typen,
                    'declaration': GetLocalType(ordinal,ida_typeinf.PRTYPE_TYPE + ida_typeinf.PRTYPE_SEMI + ida_typeinf.PRTYPE_MULTI)
                })
                count += 1
        print('[+] %d local types have been added.' % count)
        # save data.
        with open(file_name,'w') as file:
            file.write(json.dumps(j,indent=4))
        print('[+] data saved to: %s' % file_name)

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class loadOriginalData(ida_kernwin.action_handler_t):
    NAME = 'helper:loadOriginalData'
    TEXT = "Load original data (JSON)"
    TOOLTIP = "Import original data generated by LL-HeaderGen."

    def __init__(self, core):
        ida_kernwin.action_handler_t.__init__(self)
        self.core = core

    def activate(self, ctx):
        msgBox.showwarning('Warnning','Helper will load originalData into IDB, please backup the IDB at first.')
        file_name = askFile.askopenfilename(
            title = 'Chose originalData json.',
            filetypes = [('JSON','*.json'),('All files','*')],
            initialdir = os.getcwd()
            )
        print('[+] Original data chosed: %s' % file_name)
        print('[+] Parsing ...')
        file_data = open(file_name)
        original_data = json.load(file_data)
        file_data.close()
        
        # some information
        print('[i]     function %d.' % len(original_data['fn_list']))
        print('[i]     class    %d.' % len(original_data['identifier']['class']))
        print('[i]     struct   %d.' % len(original_data['identifier']['struct']))

        # public, public.static
        # private, private.static
        # protected, protected.static
        # virtual, virtual.unordered
        # parent_types, child_types
        # vtbl_entry

        image_base = ida_nalt.get_imagebase()

        def handle_para(typeName):
            a = typeName.split(' ')
            rtn = ''
            if '<' in typeName or '(' in typeName:
                return None
            add = []
            for i in a:
                filter = ['class','struct','enum','...']
                if i in filter:
                    continue
                elif i == '&':
                    add.append('*')
                elif i == '&&':
                    add.append('**')
                elif i == 'const':
                    if len(add) - 1 < 0:
                        print(typeName)
                        continue
                    temp = add[len(add)-1]
                    add[len(add)-1] = i
                    add.append(temp)
                else:
                    add.append(i)
            for i in add:
                rtn = rtn + i + ' '
            return rtn[0:len(rtn)-1]

        # test
        rva = 9192256
        ea = image_base + rva
        cfunc = decompile(ea)
        a = [
            handle_para('class DirectoryPackWithEncryptionAccessStrategy &') + ' a1',
            handle_para(original_data['classes']['DirectoryPackWithEncryptionAccessStrategy']['public'][0]['params'][0]) + ' a2',
            handle_para(original_data['classes']['DirectoryPackWithEncryptionAccessStrategy']['public'][0]['params'][1]) + ' a3',
        ]
        print(a)
        b = Utils.fixIdaBugAndGetArguments(cfunc)
        b[0].set_lvar_type(a[0])
        b[1].set_lvar_type(a[1])
        b[2].set_lvar_type(a[2])
        Utils.changeVariableType(ea,b[0],a[0])
        Utils.changeVariableType(ea,b[1],a[1])
        Utils.changeVariableType(ea,b[2],a[2])
        

    """

        def handle_func(a):
            pass

        for type,data in original_data['classes'].items():
            if 'public' in data:
                for i in data['public']:
                    handle_func(i)
            if 'private' in data:
                for i in data['private']:
                    handle_func(i)
            if 'protected' in data:
                for i in data['protected']:
                    handle_func(i)
            if 'virtual' in data:
                for i in data['virtual']:
                    handle_func(i)
            if 'virtual.unordered' in data:
                for i in data['virtual.unordered']:
                    handle_func(i)
    """

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

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
        return_type = Utils.cleanType(func_detail[0:func_detail.find(_call)])
        call_args = str()
        return_args = str()
        FirstArg = True
        for i in Utils.fixIdaBugAndGetArguments(func_data):
            if FirstArg and i.name == 'this':
                arg_name = 'self'
            else:
                arg_name = i.name
            call_args = call_args + Utils.cleanType(str(i.tif)) + ' ' + arg_name + ', '
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
        return_type = Utils.cleanType(func_detail[0:func_detail.find(_call)])
        call_args = str()
        return_args = str()
        FirstArg = True
        for i in Utils.fixIdaBugAndGetArguments(func_data):
            if FirstArg:
                this_pointer_type = Utils.cleanType(str(i.tif),True)
                FirstArg = False
            else:
                call_args = call_args + Utils.cleanType(str(i.tif)) + ' ' + i.name + ', '
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
        return_type = Utils.cleanType(func_detail[0:func_detail.find(_call)])
        call_args = str()
        return_args = str()
        FirstArg = True
        for i in Utils.fixIdaBugAndGetArguments(func_data):
            if FirstArg:
                FirstArg = False
                continue
            call_args = call_args + Utils.cleanType(str(i.tif)) + ' ' + i.name + ', '
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
        return_type = Utils.cleanType(func_detail[0:func_detail.find(_call)])
        call_types = str()
        for i in Utils.fixIdaBugAndGetArguments(func_data):
            call_types = call_types + Utils.cleanType(str(i.tif)) + ', '
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
    export,
    loadOriginalData,
    asTHook,
    asTInstanceHook,
    asTClasslessInstanceHook,
    asSymCall
]