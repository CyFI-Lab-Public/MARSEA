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
import networkx as nx
import pydot
from networkx.drawing.nx_pydot import graphviz_layout

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

def dump_funcs_with_args(proj, funcs):
    with open(str(Path(proj)/'s2e-last'/'funcs_with_args'), 'w') as f:
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

def dump_all_funcs(proj, funcs):
    with open(str(Path(proj)/'s2e-last'/'all_funcs'), 'w') as f:
        for func in funcs:
            if not func.name:
                continue

            f.write(func.module+": "+func.name+"\n")

def dump_all_modules(proj, modules):
    with open(str(Path(proj)/'s2e-last'/'all_modules'), 'w') as f:
        for module in modules:
            f.write(module+"\n")

def dump_tag_graph(proj, tag_graph):
    pos = graphviz_layout(tag_graph, prog="dot")
    nx.draw_networkx(tag_graph, pos, width=0.1, node_size=1, font_size=4, arrowsize=1, with_labels=True)
    plt.savefig(str(Path(proj)/'s2e-last'/'tag_graph.pdf'))
    plt.show()
    plt.clf()

def generate_block_coverage(proj):
    cmd = 's2e coverage basic_block --disassembler=r2 '+Path(proj).name
    p = Popen(shlex.split(cmd), stdout=PIPE, stderr=PIPE)
    out, err = p.communicate()
    out = out.decode('utf-8')
    err = err.decode('utf-8')
    output = err.split('\n')

    print(output)
    
    with open(str(Path(proj)/'s2e-last'/'basic_block_coverage.txt'), 'w') as f:
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

def build_funcs_from_cyfi(cyfi):
    state_func_dict = {}
    cyficontent = Path(cyfi).open(errors='replace').readlines()
    cyficontent = Utils.reorganize(cyficontent)

    current_state = 0

    for line in cyficontent:
        result = re.search("State (\d+)]", line)

        if result is not None:
            current_state = int(result.group(1))

            if not current_state in state_func_dict:
                state_func_dict[current_state] = []

        result = re.search("state (\d+) with condition", line)

        func = Func.analyze_line(line)

        arg_tag = re.search("([a-zA-Z]+) (\d) Argument Tag: (.*)", line)

        if result is not None:
            new_state = result.group(1)

            if int(new_state) != current_state:
                state_func_dict[current_state].append(int(new_state))

        elif func:
            state_func_dict[current_state].append(func)

        elif arg_tag is not None:
            func_name = arg_tag.group(1)
            arg_index = int(arg_tag.group(2))
            tag = arg_tag.group(3)

            if check_func_arg_use(func_name, arg_index):
                # Now check if it is already being logged or not through our function model
                # Check most recent func in current_state
                found = False
                for ele in reversed(state_func_dict[current_state]):
                    if isinstance(ele, Func.Func):
                        if ele.name == func_name and ele.tag_in == tag:
                            found = True
                    break

                if not found:
                    func = Func.Func()
                    func.name = func_name
                    func.tag_in = tag
                    state_func_dict[current_state].append(func)

        else:
            pass

    return state_func_dict

def build_func_graph(state_func_dict):
    check_states = set()

    if 0 not in state_func_dict:
        graph = nx.DiGraph()
        return graph

    graph = nx.DiGraph()

    for state_id in sorted(state_func_dict):
        parent_node = None
        pre_func_lst = []
        on_going_lst = []

        for idx, func in enumerate(state_func_dict[state_id]):

            # if state id is in the graph, replace that number node
            if state_id in graph.nodes and state_id != 0:
                # Should only have one in edge
                try:
                    parent_node = list(graph.in_edges(state_id))[0][0]
                except:
                    print(proj, "more than one edge")

                graph.remove_node(state_id)

            if isinstance(func, int):
                # Exception: the list starts with int, in this case, the parent_node should not be empty
                if len(on_going_lst) == 0:
                    if parent_node == None:
                        if not state_id == 0:
                            assert(parent_node != None)
                        else:
                            parent_node = 0
                    graph.add_edge(parent_node, func)
                else:
                    graph.add_edge(tuple(on_going_lst), func)

                if idx + 1 < len(state_func_dict[state_id]) and not isinstance(state_func_dict[state_id][idx+1], int):
                    # Will get out of this region, time to link pre_func_lst and on_going_lst
                    # |----pre_func_lst----| 1 2 3 |----on_going_lst-----| 4 5 6 here | ---

                    # It's possible that the func list looks like this
                    # 1, func,...,
                    # in this case, on_going_lst now can be empty

                    if on_going_lst:
                        graph.add_node(tuple(on_going_lst))

                    if pre_func_lst:
                        graph.add_edge(tuple(pre_func_lst), tuple(on_going_lst))

                    pre_func_lst = on_going_lst
                    on_going_lst = []
                if idx + 1 == len(state_func_dict[state_id]):

                    # It's possible that function list is only a list of integer
                    if on_going_lst:
                        graph.add_node(tuple(on_going_lst))

                    if pre_func_lst:
                        graph.add_edge(tuple(pre_func_lst), tuple(on_going_lst))

            else:
                on_going_lst.append(func)

                # If next one is a number (state_id), add the current func list to graph
                if idx + 1 < len(state_func_dict[state_id]) and isinstance(state_func_dict[state_id][idx+1], int):
                    graph.add_node(tuple(on_going_lst))

                    if parent_node is not None:
                        graph.add_edge(parent_node, tuple(on_going_lst))
                        parent_node = None

                # If already meet the end of list, same, add current function list to graph
                if idx + 1 == len(state_func_dict[state_id]):

                    graph.add_node(tuple(on_going_lst))

                    if pre_func_lst:
                        graph.add_edge(tuple(pre_func_lst), tuple(on_going_lst))

                    if parent_node is not None:
                        graph.add_edge(parent_node, tuple(on_going_lst))
                        parent_node = None


    # In this process, we may introduce empty node before real root node when pre_func_lst is empty
    # It is hard to prune in the loop bc if we say dont add edge from pre_func_lst to on_going_lst
    # when pre_func_lst is empty, on_going_lst miss the chance to be added to the graph.
    # However, if we add on_going_lst anyways,
    return graph

def get_rid_of_state_id(func_graph):
    graph = nx.DiGraph()

    for edge in func_graph.edges:
        src = edge[0]
        sink = edge[1]

        if isinstance(src, int):
            new_src = []
        else:
            new_src = [x for x in src if not isinstance(x, int)]

        if isinstance(sink, int):
            new_sink = []
        else:
            new_sink = [x for x in sink if not isinstance(x, int)]

        if new_src:
            graph.add_node(tuple(new_src))

        if new_sink:
            graph.add_node(tuple(new_sink))

        if new_src and new_sink:
            graph.add_edge(tuple(new_src), tuple(new_sink))

    return graph

def visualize_graph(func_graph):
    graph = nx.DiGraph()

    func_name = {}

    func_name_name = {}

    for edge in func_graph.edges:
        src = edge[0]
        sink = edge[1]

        for ind, func in enumerate(src):

            if not func in func_name:

                if not func.name in func_name_name:
                    func_name_name[func.name] = 0
                else:
                    func_name_name[func.name] += 1

                new_index = func_name_name[func.name]

                func_name[func] = new_index

            if ind == len(src) - 1:
                graph.add_node(func.name+'_'+str(func_name[func]))
            else:
                next_func = src[ind+1]

                if not next_func in func_name:

                    if not next_func.name in func_name_name:
                        func_name_name[next_func.name] = 0
                    else:
                        func_name_name[next_func.name] += 1

                    next_new_index = func_name_name[next_func.name]

                    func_name[next_func] = next_new_index

                graph.add_edge(func.name+'_'+str(func_name[func]), next_func.name+'_'+str(func_name[next_func]))

        for ind, func in enumerate(sink):

            if not func in func_name:

                if not func.name in func_name_name:
                    func_name_name[func.name] = 0
                else:
                    func_name_name[func.name] += 1

                new_index = func_name_name[func.name]

                func_name[func] = new_index

            if ind == len(sink) - 1:
                graph.add_node(func.name+'_'+str(func_name[func]))
            else:
                next_func = sink[ind+1]

                if not next_func in func_name:

                    if not next_func.name in func_name_name:
                        func_name_name[next_func.name] = 0
                    else:
                        func_name_name[next_func.name] += 1

                    next_new_index = func_name_name[next_func.name]

                    func_name[next_func] = next_new_index

                graph.add_edge(func.name+'_'+str(func_name[func]), next_func.name+'_'+str(func_name[next_func]))

        if src and sink:
            graph.add_edge(src[-1].name+'_'+str(func_name[src[-1]]), sink[0].name+'_'+str(func_name[sink[0]]))

    return graph

def proj_build_func_graph(proj):
    fproj = Path(proj)

    sample_name = Utils.get_sample_name(fproj)

    cyfi_txts = Utils.find_all_files(proj, "cyfi.txt", True)

    state_func_dict = {}

    for cyfi in cyfi_txts:
        cyfi_state_func_dict = build_funcs_from_cyfi(cyfi)

        for state_id, funclist in cyfi_state_func_dict.items():
            if not state_id in state_func_dict:
                state_func_dict[state_id] = []

            state_func_dict[state_id].extend(funclist)


    func_graph = build_func_graph(state_func_dict)

    new_func_graph = get_rid_of_state_id(func_graph)

    new_visual_func_graph = visualize_graph(new_func_graph)

    nx.write_gpickle(new_func_graph, fproj/"s2e-last"/"func_graph")
    
    pos = graphviz_layout(new_visual_func_graph, prog="dot")
    nx.draw_networkx(new_visual_func_graph, pos, width=0.1, node_size=1, font_size=4, arrowsize=1, with_labels=True) 
    plt.savefig(str(fproj/'s2e-last'/'visual_func_graph.pdf'))
    plt.show()
    plt.clf()

    return new_func_graph

if __name__ == "__main__":
    proj = sys.argv[1]

    fproj = Path(proj)

    sample_name = Utils.get_sample_name(proj)

    (fproj/(sample_name+'.disas')).unlink(True)

    graph = proj_build_func_graph(proj)

    funcs_with_args_tags = collect_funcs_with_args_and_tags(proj)
    dump_funcs_with_args(proj, funcs_with_args_tags)

    all_funcs = collect_all_funcs(proj)
    dump_all_funcs(proj, all_funcs)

    all_modules = collect_all_loaded_modules(proj)
    dump_all_modules(proj, all_modules)

    tag_graph = generate_tag_graph(funcs_with_args_tags)
    dump_tag_graph(proj, tag_graph)

    generate_block_coverage(proj)
