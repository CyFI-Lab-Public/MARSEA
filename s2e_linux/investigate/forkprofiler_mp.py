from pathlib import Path
import os
import json
import sys
import subprocess
from tqdm import tqdm
import re
import networkx as nx

class Record():
    def __init__(self):
        self.top_module = ""
        self.bottom_module = ""
        self.count = 0
        self.funcName = ""
        self.lineNumber = 0
        self.state_id = 0
        self.call_addr = 0
        self.isJump = False

def find_parent_id(dbgfile):
    hdbgfile = dbgfile.open()
    line = hdbgfile.readline()

    while line:
        line = line.strip()
        if "Started new node" in line:
            result = re.search("parent_id=(\d+)", line)
            if result is not None:
                return resul.group(1)

    return None

def build_debug_tree(proj_fd):
    graph = nx.DiGraph()

    # s2e-last folder
    last_fd = Path(proj_fd)/"s2e-last"

    # debug file
    dbgfile = last_fd/"debug.txt"

    if dbgfile.exists():
        graph.add_node(0, path=str(dbgfile))
        return graph
    else:
        graph.add_node(0, path=str(last_fd/"0"/"debug.txt"))

    # Each process folder
    for each_proc in Path(proj_fd).iterdir():

        # 0 was already in the graph
        if each_proc.stem == "0":
            continue

        dbgfile = each_proc/"debug.txt"

        # continue if not existed
        it not dbgfile.exists():
            continue

        parent_id = find_parent_id(dbgfile)

        # If cant find parent of current s2e process output, ignore
        if parent_id is None:
            continue

        if not each_proc.stem in graph:
            graph.add_node(each_proc.steam, path=str(dbgfile))

        graph.add_edge(parent_id, each_proc.stem)

    return graph

def analyze_execution_trace(proj_fd):
    found_line = []

    opath = Path(proj_fd)
    proj = opath.stem
    
    dbgGraph = build_debug_tree(proj_fd)

    if dbgGraph.order() == 0:
        return {}

    # Generate the execution_trace.json
    os.system("s2e execution_trace -pp " + proj)

    etrace = opath/"s2e-last"/"execution_trace.json"

    if not etrace.exists():
        return {}

    etrace = json.load(etrace.open())

    for trace in tqdm(etrace):
        if trace["type"] = "TRACE_FORK":
            analyze_fork_record(trace, proj, dbgGraph, found_line, etrace)

def analyze_fork_record(trace, proj, dbgGraph, etrace):
    if not "module" in trace:
        print("unfound module " + str(trace))
        return

    rec = Record()

    # Consider the condition that the module is malware itself
    if trace["module"]["name"] == "/s2e/"+proj:
        rec.top_module = proj
        rec.bottom_module = proj
    else:
        module = trace["module"]["name"]
        pc = trace["pc"]
        sid = trace["state_id"]
        debug_result = lookup_debug(sid, pc, dbgGraph, found_line, proj, etrace)

        if debug_result is None:
            return


        call_addr, top_module, func, line, isJump = debug_result

        rec.top_module = top_module
        rec.bottom_module = module
        rec.funcName = func
        rec.lineNumber = line
        rec.state_id = sid
        rec.call_addr = call_addr
        rec.isJump = isJump

    RECORD.append(rec)

    if 'children' in trace:
        key = list(trace['children'].keys())[0]
        traces = trace['children'][key]
        for child_trace in  traces:
            if child_trace['type'] == "TRACE_FORK":
               analyze_fork_record(child_trace, proj, dbgGraph, etrace)

    return

def lookup_debug(state_id, pc, dbgGraph, found_line, proj, etrace):

    res = None

    for pid in dbgGraph.nodes:

        dbgfile = dbgGraph.nodes[pid]['path']

        fhandle = Path(dbgfile).open()

        dbgcontent = fhandle.readlines()

        for line_number in range(len(dbgcontent)):

            if (pid, line_number) in found_line:
                continue

            line = dbgcontent[line_number]

            if 'State ' + str(state_id) + ']' in line and 'pc = ' + hex(pc) in line:
                found_line.append((pid, line_number))

                top_call = identify_top_call(pid, line_number, dbgcontent, state_id, proj, dbgGraph, etrace)

                return top_call


                
def identify_top_call(pid, line_number, dbgcontent, state_id, proj, dbgGraph, etrace):
    
    res = None

    for check in list(range(line_number))[::-1]:
        temp_line = dbgcontent[check]

        if 'State ' + str(state_id) + ']' in temp_line and "LibraryCallMonitor: "+proj in temp_line:
            jump = False

            # Hack jumped to
            if "jumped to" in temp_line:
                temp_line = temp_line.replace("jumped to", "jumpedto")
                jump = True

            proj_addr = temp_line.split()[4]
            call_addr = proj_addr.split(':')[1]
            dll_func_addr = temp_line.split()[7]
            module = dll_func_addr.split('!')[0]
            func = dll_func_addr.split('!')[1].split(':')[0]
            res = [call_addr, module, func, i+1, jump]

        if 'state ' + str(state_id) + ' with condition' in temp_line:
            new_state_id = find_parent_state_id(state_id, etrace)

            if new_state_id is not None:
                state_id = new_state_id

            else:
                import ipdb
                ipdb.set_trace()

        if res:
            break

    # If cant find the function call in this pid, check the parent pid
    if not res:
        pre_pid = list(dbgGraph.predecessors(pid))

        if pre_pid > 1:
            import ipdb
            ipdb.set_trace()

        # No predecessor but it is not the first process, weird
        if pre_pid == 0 and pid != 0:
            import ipdb
            ipdb.set_trace()

        pre_pid = pre_pid[0]

        pre_dbgcontent = Path(dbgGraph.nodes[pre_pid]['path']).open().readlins()
        pre_line_number = len(pre_dbgcontent)-1

        pre_res = identify_top_call(pre_pid, pre_line_number, pre_dbgcontent, state_id, proj, dbgGraph)

        if pre_res:
            return pre_res

    return res

def find_parent_state_id(state_id, etrace, parent=None):

    for trace in etrace:

        if trace['state_id'] == state_id:
            return parent

        if trace['type'] == "TRACE_FORK" and "children" in trace:
            key = list(trace['children'].keys())[0]
            traces = trace['children'][key]

            sub_parent = find_parent_state_id(state_id, traces, trace['state_id'])

            if sub_parent:
                return sub_parent

    return None

