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
import xmind
from xmind.core.const import *
import xml.dom
import tempfile
import os
import zipfile

_ver = '1.0.0'
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
        ida_kernwin.attach_action_to_menu("Edit/BDSDevHelper/Export structure", exportStructure.NAME, ida_kernwin.SETMENU_INS)
        # ida_kernwin.attach_action_to_menu("Edit/BDSDevHelper/Generate type tree", genGenealogy.NAME, ida_kernwin.SETMENU_INS)
        
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

def changeVariableType(ea, lvar, tpe):
    lsi = lvar_saved_info_t()
    lsi.ll = lvar
    lsi.type = tpe
    return modify_user_lvar_info(ea, MLI_TYPE, lsi)

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

class exportStructure(ida_kernwin.action_handler_t):

    NAME = "helper:exportStructure"
    TEXT = "Export all struct."
    TOOLTIP = "Export all structure information from idb."

    def __init__(self, core):
        ida_kernwin.action_handler_t.__init__(self)
        self.core = core
    
    def activate(self, ctx):
        file_name = askFile.asksaveasfilename(
            title = 'Where to save structure data?',
            filetypes = [('Json File','*.json'),('All files','*')],
            initialdir = os.getcwd()
            )
        if file_name[len(file_name)-5:] != '.json':
            file_name = file_name + '.json'
        j = list()
        added_struct = list()
        banned_prefix = [
            '_M',
            'baseclass_',
            'vn_',
            'vna_',
            'gap',
            'st_',
            'std::',
            'entt::',
            'Elf'
        ]
        for idx,sid,struct in idautils.Structs():
            struct = str(struct)
            if struct in added_struct:
                continue
            stopAndContinue = False
            for word in banned_prefix:
                if struct[:len(word)] == word:
                    stopAndContinue = True
                    break
            if stopAndContinue:
                continue
            members = []
            for offset,mem,size in idautils.StructMembers(sid):
                members.append({
                    'name': mem,
                    'type': getMemberType(sid,offset),
                    'offset': offset,
                    'size': size
                })
            added_struct.append(struct)
            j.append({
                    'struct_name': struct,
                    'members': members
                })
        with open(file_name,'w') as file:
            file.write(json.dumps(j,indent=4))
        print('[+] structure data saved to: %s' % file_name)

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class genGenealogy(ida_kernwin.action_handler_t):

    ###
    ### Incomplete.
    ### xmind need to sort all elements, but...
    ###

    NAME = 'helper:genGenealogy'
    TEXT = "Generate type tree"
    TOOLTIP = "Generate genealogy using originalData"

    def __init__(self, core):
        ida_kernwin.action_handler_t.__init__(self)
        self.core = core

    def activate(self, ctx):
        
        # load original data.
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

        # ask .xmind path.
        file_name = askFile.asksaveasfilename(
            title = 'Where to save .xmind?',
            filetypes = [('XMind File','*.xmind'),('All files','*')],
            initialdir = os.getcwd()
            )
        if file_name[len(file_name)-6:] != '.xmind':
            file_name = file_name + '.xmind'
        
        print('[+] XMind file on: %s' % file_name)

        workbook = xmind.load(file_name)
        sheet1 = workbook.getPrimarySheet()
        sheet1.createElement('test')
        root_topic = sheet1.getRootTopic()
        root_topic.setTitle('Bedrock Dedicated Server')

        applied = dict()
        for typeName,data in original_data['classes'].items():
            if not 'parent_types' in data:
                topic = root_topic.addSubTopic(topics_type=TOPIC_DETACHED)
                topic.setTitle(typeName)
                applied[typeName] = topic
        
        classes_len = len(original_data['classes'])
        loop_time = 0
        while len(applied) != classes_len:
            loop_time += 1
            print('loop time %d' % loop_time)
            if loop_time == 100:
                print('loop times error, jumpout!')
                break
            for typeName,data in original_data['classes'].items():
                if 'parent_types' in data:
                    for i in data['parent_types']:
                        if i in applied:
                            topic = root_topic.addSubTopic(topics_type=TOPIC_DETACHED)
                            topic.setTitle(typeName)
                            sheet1.createRelationship(applied[i].getID(),topic.getID())
                            applied[typeName] = topic            

        xmind.save(workbook, path=file_name)
        XMindFixer().fixXMindFile(file_name)

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
        b = fixIdaBugAndGetArguments(cfunc)
        b[0].set_lvar_type(a[0])
        b[1].set_lvar_type(a[1])
        b[2].set_lvar_type(a[2])
        changeVariableType(ea,b[0],a[0])
        changeVariableType(ea,b[1],a[1])
        changeVariableType(ea,b[2],a[2])
        

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
    exportStructure,
    genGenealogy,
    loadOriginalData,
    asTHook,
    asTInstanceHook,
    asTClasslessInstanceHook,
    asSymCall
]

## XMindFixer类来源：
## https://github.com/noemotionLi/xmind-2021-fix
## 做了少许修改，感谢原作者

class XMindFixer():

    def get_filename(self, file_name):
        f = zipfile.ZipFile(file_name)
        path_list = []

        for name in f.namelist():
            temp_list = name.split('/')
            temp_str = ''
            for i in range(name.count('/')+1):
                temp_str += '/' + temp_list[i]
                temp = temp_str.replace('/','',1)
                path_list.append(temp)
        
        path_list = list(set(path_list))
        path_list.insert(0,'META-INF')
        path_list.insert(1,'META-INF/manifest.xml')
        f.close()

        def type_check(file_path):
            if os.path.splitext(file_path)[1] == '.xml':
                type_media = 'text/xml'
            elif os.path.splitext(file_path)[1] == '.png':
                type_media = 'image/png'
            else : 
                type_media = ''
                file_path += '/'
            return type_media,file_path
        
        temp_list = []
        for wrong_path in path_list:
            media_type,file_path = type_check(wrong_path)
            temp_list.append([media_type,file_path])
        
        return temp_list

    def xml_writer(self, Attr_value):
        domImp = xml.dom.getDOMImplementation()
        doc = domImp.createDocument(None, None, None)
        rootNode = doc.createElement("manifest")

        doc.appendChild(rootNode)
        doc.createAttribute("password-hint")
        doc.createAttribute("xmlns")
        doc.createAttribute("media-type")
        doc.createAttribute("full-path")
        rootNode.setAttribute("password-hint","")
        rootNode.setAttribute("xmlns","urn:xmind:xmap:xmlns:manifest:1.0")

        def add_node(root, value):
            child = doc.createElement("file-entry")
            root.appendChild(child)
            child.setAttribute("media-type",value[0])
            child.setAttribute("full-path",value[1])
        
        for value in Attr_value:
            add_node(rootNode, value)
        
        return doc


    def fixXMindFile(self, path):
        target_list = self.get_filename(path)
        xml_doc = self.xml_writer(target_list)
        directory_name = tempfile.mkdtemp()
        xml_path = os.path.join(directory_name,"manifest.xml")

        with open(os.path.join(xml_path), 'w', encoding='utf-8') as writer:
            xml_doc.writexml(writer, indent='\n', addindent="", newl="", encoding="utf-8")
        
        f = zipfile.ZipFile(path,'a')
        f.write(xml_path,'META-INF/manifest.xml')
        f.close()