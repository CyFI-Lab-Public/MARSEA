import Utils
import Func
import sys
import re
import networkx as nx
import matplotlib.pyplot as plt
import json
from pathlib import Path
import os
from subprocess import Popen, PIPE, STDOUT
import shlex

win32 = []

S2EDIR = os.getenv('S2EDIR')

with open('win32.json') as f:
    win32 = json.load(f)

def check_func_arg_use(func_name, arg_index):
    # Check if func_name will use arg_index th argument
    for func in win32:
        if func['name'] == func_name:
            if 'param_meta' in func:
                if arg_index >= len(func['param_meta']):
                    return False
                inout = func['param_meta'][arg_index]

                if 'in' in inout:
                    return True
                else:
                    return False

    return False

def collect_funcs_with_args_and_tags(proj):

    funcs = set()

    cyfi_txts = Utils.find_all_files(proj, "cyfi.txt", True)

    for cyfi in cyfi_txts:
        cyficontent = Path(cyfi).open(errors='replace').readlines()
        cyficontent = Utils.reorganize(cyficontent)

        for line in cyficontent:
            func = Func.analyze_line(line)

            arg_tag = re.search("([a-zA-Z]+) (\d) Argument Tag: (.*)", line)

            if arg_tag is not None:
                func_name = arg_tag.group(1)
                arg_index = int(arg_tag.group(2))
                tag = arg_tag.group(3)

                if check_func_arg_use(func_name, arg_index):
                    found = False

                    for ele in funcs:
                        if ele.name == func_name and ele.tag_in == tag:
                            found = True

                        break

                    if not found:
                        func = Func.Func()
                        func.name = func_name
                        func.tag_in = tag
                        funcs.add(func)

            elif func:
                funcs.add(func)

    return funcs

def collect_all_funcs(proj):

    funcs = set()

    dbg_txts = Utils.find_all_files(proj, "debug.txt", True)

    sample_name = Utils.get_sample_name(proj)

    for dbg in dbg_txts:
        dbgcontent = Path(dbg).open(errors='replace').readlines()
        dbgcontent = Utils.reorganize(dbgcontent)

        for line in dbgcontent:
            func = Func.analyze_libcall_line(line, sample_name)
            if func is not None:
                funcs.add(func)

    return funcs

def collect_all_loaded_modules(proj):

    modules = set()

    dbg_txts = Utils.find_all_files(proj, "debug.txt", True)

    for dbg in dbg_txts:
        dbgcontent = Path(dbg).open(errors='replace').readlines()
        dbgcontent = Utils.reorganize(dbgcontent)

        for line in dbgcontent:
            if 'Loading module from disk ' in line:
                content = line.split('Loading module from disk ')[1].strip()
                modules.add(content)

    return modules

def generate_tag_graph(funcs):
    tag_graph = nx.DiGraph()

    for func in funcs:
        if func.tag_in and func.tag_out:
            tag_in_name = Utils.get_func_name_from_tag(func.tag_in)
            tag_out_name = Utils.get_func_name_from_tag(func.tag_out)
            tag_graph.add_edge(tag_in_name, tag_out_name)

        elif func.tag_in and not func.tag_out:
            tag_in_name = Utils.get_func_name_from_tag(func.tag_in)
            tag_graph.add_edge(tag_in_name, func.name)

        elif not func.tag_in and func.tag_out:
            tag_out_name = Utils.get_func_name_from_tag(func.tag_out)
            # tag_graph.add_node(tag_out_name)

        else:
            continue

    return tag_graph

def dump_funcs_with_args(funcs):
    with open('funcs_with_args', 'w') as f:
        for func in funcs:

            if not func.args:
                continue

            f.write(func.name+" (")
            for ind, arg in enumerate(func.args):
                if ind == len(func.args) - 1:
                    f.write(arg+") ")
                else:
                    f.write(arg+", ")

            if func.ret:
                f.write("ret: "+str(func.ret))

            f.write("\n")

def dump_all_funcs(funcs):
    with open('all_funcs', 'w') as f:
        for func in funcs:
            if not func.name:
                continue

            f.write(func.module+": "+func.name+"\n")

def dump_all_modules(modules):
    with open('all_modules', 'w') as f:
        for module in modules:
            f.write(module+"\n")


def dump_tag_graph(tag_graph):
    nx.draw(tag_graph, with_labels=True)
    plt.savefig('tag_graph', dpi=300, bbox_inches='tight')
    plt.show()

def generate_block_coverage(proj):
    cmd = 's2e coverage basic_block --disassembler=r2 '+Path(proj).name
    p = Popen(shlex.split(cmd), stdout=PIPE, stderr=PIPE)
    out, err = p.communicate()
    out = out.decode('utf-8')
    err = err.decode('utf-8')
    output = err.split('\n')

    print(output)
    
    with open('basic_block_coverage.txt', 'w') as f:
        for line in output:
            if 'Total basic blocks' in line:
                f.write(line+'\n')

            if 'Covered basic blocks' in line:
                line = line[:line.rfind(')')+1]
                f.write(line+'\n')
    # os.system('s2e coverage basic_block --disassembler=r2 '+Path(proj).name)

def calculate_code_coverage(proj):
    generate_block_coverage(proj)

    p = Popen(['r2', '-i', str(Path(S2EDIR)/'install'/'bin'/'r2_highlight_basic_blocks.py'), Path(proj).name], stdout=PIPE, stdin=PIPE, stderr=STDOUT)
    grep_output = p.communicate(input=str(Path(proj)/'s2e-last'/Path(proj).name+'_coverage.json')+'\n')[0]
    print(grep_output)

if __name__ == "__main__":
    proj = sys.argv[1]

    funcs_with_args_tags = collect_funcs_with_args_and_tags(proj)
    dump_funcs_with_args(funcs_with_args_tags)

    all_funcs = collect_all_funcs(proj)
    dump_all_funcs(all_funcs)

    all_modules = collect_all_loaded_modules(proj)
    dump_all_modules(all_modules)

    tag_graph = generate_tag_graph(funcs_with_args_tags)
    dump_tag_graph(tag_graph)

    generate_block_coverage(proj)
