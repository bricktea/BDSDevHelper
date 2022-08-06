import json
import os
import GOOD
import tkinter.filedialog as askFile

structure_file = askFile.askopenfilename(
    title = 'Chose structure data json.',
    filetypes = [('JSON','*.json'),('All files','*')],
    initialdir = os.getcwd())

save_to_dir = askFile.askdirectory(
    title = 'Where to save markdown?',
    initialdir = os.getcwd())
os.mkdir('%s/structure' % save_to_dir)
os.mkdir('%s/enums' % save_to_dir)

data = {
    'structure': dict(),
    'enums': dict()
}

with open(structure_file,'r') as file:
    j = json.loads(file.read())
    windows_banned_filename = ['\\','/',':','*','?','"','<','>','|']
    
    # sort structure data
    for struct in j['structure']:
        short_name = struct['struct_name'][:1].upper()
        if short_name in windows_banned_filename:
            short_name = '$'
        cont = data['structure']
        if not short_name in cont:
            cont[short_name] = list()
        cont[short_name].append(struct)

    # sort enums data
    for enum in j['enums']:
        short_name = enum['enum_name'][:1].upper()
        if short_name in windows_banned_filename:
            short_name = '$'
        cont = data['enums']
        if not short_name in cont:
            cont[short_name] = list()
        cont[short_name].append(enum)

def is_stupid(text:str):
    if text in GOOD.YES:
        return False
    for i in GOOD.CONTENT:
        if text.lower().find(i.lower()) != -1:
            return True
    return False

max_size = 500000

for short_name in data['structure']:
    text = str()
    num = 0
    def try_save(force=False):
        global text,num
        if len(text) > max_size or force:
            if num > 0:
                filename = '%s/structure/%s~%d.md' % (save_to_dir,short_name,num)
                text = '# %s~%d\n' % (short_name,num) + text
            else:
                filename = '%s/structure/%s.md' % (save_to_dir,short_name)
                text = '# %s\n' % short_name + text
            with open(filename,'w') as file:
                file.write(text)
            text = str()
            num += 1
    for struct in data['structure'][short_name]:
        if is_stupid(struct['struct_name']):
            continue
        if not 'declaration' in struct:
            text = text + "### `%s`\n" % struct['struct_name']
            text = text + "Offset | Type | Name\n"
            text = text + "-|-|-|-\n"
            for member in struct['members']:
                name = member['name']
                type = member['type']
                if is_stupid(name):
                    name = '?'
                if is_stupid(type):
                    type = '?'
                text = text + "%s | (%s) `%s` | %s\n" % (member['offset'],member['size'],type,name)
            text = text + "\n\n"
        else:
            if is_stupid(struct['declaration']):
                continue
            text = text + "### `%s`\n" % struct['struct_name']
            text = text + "```\n%s\n```\n\n" % struct['declaration']
        try_save()
    try_save(True)

for short_name in data['enums']:
    text = str()
    num = 0
    def try_save(force=False):
        global text,num
        if len(text) > max_size or force:
            if num > 0:
                filename = '%s/enums/%s~%d.md' % (save_to_dir,short_name,num)
                text = '# %s~%d\n' % (short_name,num) + text
            else:
                filename = '%s/enums/%s.md' % (save_to_dir,short_name)
                text = '# %s\n' % short_name + text
            with open(filename,'w') as file:
                file.write(text)
            text = str()
            num += 1
    for enum in data['enums'][short_name]:
        if is_stupid(enum['enum_name']):
            continue
        if not 'declaration' in enum:
            text = text + "### `%s`\n" % enum['enum_name']
            text = text + "Name | Value\n"
            text = text + "-|-\n"
            for member in enum['members']:
                name = member['name']
                if is_stupid(name):
                    name = '?'
                text = text + "%s | `%s`\n" % (name,member['value'])
            text = text + "\n\n"
        else:
            if is_stupid(enum['declaration']):
                continue
            text = text + "### `%s`\n" % enum['enum_name']
            text = text + "```\n%s\n```\n\n" % enum['declaration']
        try_save()
    try_save(True)