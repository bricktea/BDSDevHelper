import json
import os
import tkinter.filedialog as ask_file

older_data = {}
newer_data = {}

with open(ask_file.askopenfilename(
    title = 'Choose an older structure size data file.',
    filetypes = [('JSON','*.json'),('All files','*')],
    initialdir = os.getcwd()), 'r') as file:
    older_data = json.load(file)

with open(ask_file.askopenfilename(
    title = 'Choose an newer structure size data file.',
    filetypes = [('JSON','*.json'),('All files','*')],
    initialdir = os.getcwd()), 'r') as file:
    newer_data = json.load(file)

bds_data = None

if os.path.exists('originalData.json'):
    with open('originalData.json') as file:
        bds_data = json.load(file)

changed_types = {}

for type_name in newer_data:
    
    if type_name not in older_data:
        continue
    newer = newer_data[type_name]['final_guessed_size']
    older = older_data[type_name]['final_guessed_size']

    if newer != older and newer != 0 and older != 0:
        changed_types[type_name] = {
            'after': newer,
            'before': older,
            'delta': newer - older
        }

marked_to_delete = set()

if bds_data:
    for type_name in changed_types:
        if type_name not in bds_data['classes']:
            continue
        parents = bds_data['classes'][type_name]['parent_types'] if 'parent_types' in bds_data['classes'][type_name] else []
        for parent in parents:
            if parent in changed_types and changed_types[parent]['delta'] == changed_types[type_name]['delta']:
                marked_to_delete.add(type_name)


for type_name in marked_to_delete:
    changed_types.pop(type_name)

result = """#### Changed structure(s):
Type Name | Before | After | Delta
-|-|-|-
"""
for type_name in changed_types:
    this = changed_types[type_name]
    m = this['after'] - this['before']
    result += '`%s` | %d | %d | %s\n' % (type_name, this['before'], this['after'], '+' + str(m) if m > 0 else m)

with open('TilChanges.md', 'w') as file:
    file.write(result)

print('All works done.')
