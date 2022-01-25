from pathlib import Path
import os
import json
import sys
import subprocess
import tqdm
import re

PROJ = ""
FOUND_LINE = []
DEBUG = []
RECORD = []

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

def analyze_record():
    res = {}

    for rec in RECORD:
        if not rec.funcName in res:
            res[rec.funcName] = 0
        res[rec.funcName] += 1

    return res

def get_line_number_from_func(func):
    res = []

    for rec in RECORD:
        if rec.funcName == func:
            res.append(rec.lineNumber)

    return res

def run_fork(proj_name):
    result = subprocess.run(['s2e', 'forkprofiler', proj_name], stdout=subprocess.PIPE)
    output = result.stdout.decode('utf-8')
    return output

def analyze_fork(output):
    result = []
    output = [x.strip() for x in output]
    index = output.index("# process_pid module_path:address fork_count source_file:line_number (function_name)")
    analyze_result = output[index+1:]

    for line in analyze_result:
        info = line.split()
        pid = int(info[0].strip())
        dll_path = info[1].strip().split(":")[0]
        dll_name = Path(dll_path).stem()
        addr = info[1].strip().split(":")[1]
        count = info[2].strip()
        result.append([pid, dll_name, addr, count]) 

    return result

def lookup_debug(state_id, pc):
    global FOUND_LINE

    res = None
    
    for i in range(len(DEBUG)):

        if i in FOUND_LINE:
            continue

        line = DEBUG[i]

        if '[State ' + str(state_id) + ']' in line and 'pc = ' + hex(pc) in line:
            FOUND_LINE.append(i)

            for check in list(range(i))[::-1]:
                temp_line = DEBUG[check]
                if '[State ' + str(state_id) + ']' in temp_line and "LibraryCallMonitor: "+PROJ in temp_line:
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
                    break

                if 'state ' + str(state_id) + ' with condition' in temp_line:
                    new_state_id = find_parent_state_id(check)
                    
                    if new_state_id is not None:
                        state_id = new_state_id

                    else:
                        import ipdb
                        ipdb.set_trace()

        if res:
            break

    return res

def find_parent_state_id(index):
    for check in list(range(index))[::-1]:
        temp_line = DEBUG[check]

        result = re.search("Forking state (\d+) at pc", temp_line)

        if result is not None:
            new_state_id = result.group(1)
            return int(new_state_id)

    return None

def analyze_fork_record(trace):
    if not 'module' in trace:
        print("unfound module " + str(trace))
        return

    rec = Record()

    # Consider the condition that the module is malware itself
    if trace['module']['name'] == "/s2e/"+PROJ:
        rec.top_module = PROJ
        rec.bottom_module = PROJ

    else:
        module = trace['module']['name']
        pc = trace['pc']
        sid = trace['state_id']
        debug_result = lookup_debug(sid, pc)

        # Case: ProgArgs
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
               analyze_fork_record(child_trace)

    return

def load_execution_trace(etrace_file):
    etrace = json.load(Path(etrace_file).open())

    for trace in tqdm.tqdm(etrace):
        if trace['type'] == "TRACE_FORK":
            analyze_fork_record(trace)

def analyze_execution_trace(proj_fd):
    global PROJ
    global DEBUG
    global FOUND_LINE
    global RECORD

    FOUND_LINE = []
    RECORD = []
    PROJ = ""
    DEBUG = []

    opath = Path(proj_fd)
    PROJ = opath.stem
    # Generate the executraion_trace.json
    os.system('s2e execution_trace -pp ' + PROJ)

    dfile = opath/"s2e-last"/"debug.txt"
    etrace = opath/"s2e-last"/"execution_trace.json"

    if not (dfile.exists() and etrace.exists()):
        return []

    DEBUG = [x.strip() for x in Path(dfile).open().readlines()]

    load_execution_trace(etrace)

    return RECORD

def main():
    if len(sys.argv) != 2:
        print("Plase pass the path to s2e-last as argument")
        exit()

    global PROJ
    global DEBUG

    opath = Path(sys.argv[1])
    dfile = opath/"debug.txt"
    etrace = opath/"execution_trace.json"
  
    PROJ = opath.parent.stem
    DEBUG = [x.strip() for x in Path(dfile).open().readlines()]

    load_execution_trace(etrace)

    import ipdb
    ipdb.set_trace()

    # s2e_fork_profiler_output = run_fork(opath.parent.stem)
    # fork_profiler_outputs = analyze_fork(s2e_fork_profiler_output)

if __name__ == "__main__":
    main()
