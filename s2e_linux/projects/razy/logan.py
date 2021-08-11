import re
import regex
import json
import os

lineparser = regex.compile(
    r'^\d+ \[State (\d+)\].*\[HLOG\] (\w+)\((.*)\)(?: Ret: (.*))?$')
argsplitter = regex.compile(r'(?:((?:0[xX])?[0-9a-fA-F]+)|A"(.*?)")(?:, |$)')
jsonlog = []

statelogs = {}

urls = set()


def parse_line(line):
    matches = lineparser.match(line)

    if matches:
        stateid, funcname, args, ret = matches.groups()

        fixedargs = list()

        for match in argsplitter.finditer(args):
            for group in match.groups():
                if group is not None:
                    fixedargs.append(group)
                    break

        return pack(stateid, funcname, fixedargs, ret)

    return None


def pack(stateid, funcname, args, ret):
    return {
        "state": stateid,
        "func": funcname,
        "args": args,
        "ret": ret,
    }


def unpack(entry):
    return (entry[f] for f in ["state", "func", "args", "ret"])


def _extract_traces(statelogs):

    starts = ['InternetOpenA', 'InternetOpenW', 'WinHttpOpen']
    conn = ['InternetConnectA', 'InternetConnectW', 'WinHttpConnect']
    o_req = ['HttpOpenRequestA', 'HttpOpenRequestW', 'WinHttpOpenRequest']
    rets = {}
    for i in statelogs:
        for state in statelogs[i]:
            if state['func'] in starts:
                # sanity check...all starts should have a ret
                # if not, we need to update it
                if 'ret' in state.keys():
                    rets[state['ret']] = state
    traces = {}
    trace_num = 0

    for ret, info in rets.items():

        traces[trace_num] = {}
        traces[trace_num][info['func']] = {
            'args': info['args'], 'ret': info['ret']}

        t_ret = ret
        for i in statelogs:
            req = ''
            requests = set()
            for state in statelogs[i]:
                # find the state with the return address as an input handle
                # store function information using the input handle
                # update the handle to the new return (if applicable), else
                # continue using the handle
                if t_ret == state['args'][0]:
                    traces[trace_num][state['func']] = {
                        'args': state['args'], 'ret': state['ret']}
                    t_ret = state['ret'] if state['ret'] else t_ret

                # start building the request, e.g., InternetConnectA -> HttpOpenRequestA
                # e.g. req = GET twitter.com:80/pidoras6
                # store req in a set to avoid duplication
                if state['func'] in conn:
                    # req = twitter.com:80
                    req = f"{state['args'][1]}:{state['args'][2]}"
                elif state['func'] in o_req:
                    # req = GET twitter.com:80/pidoras6
                    req = f"{state['args'][1]} {req}{state['args'][2]}"
                    requests.add(req)
                    req = ''
             
        traces[trace_num]['req'] = list(requests)
        trace_num += 1


        
    return traces

def extract_traces(statelogs):

    starts = ['socket', 'InternetOpenUrlA', 'InternetOpenUrlW', 'InternetOpenA', 'InternetOpenW', 'WinHttpOpen']
    conn = ['connect', 'InternetOpenUrlA', 'InternetOpenUrlW', 'InternetConnectA', 'InternetConnectW', 'WinHttpConnect']
    o_req = ['HttpOpenRequestA', 'HttpOpenRequestW', 'WinHttpOpenRequest']
    ends = ['closesocket', 'CloseHandle', 'InternetCloseHandle', 'WinHttpCloseHandle']

    rets = {}
    for i in statelogs:
        for state in statelogs[i]:
            if state['func'] in starts:
                # sanity check...all starts should have a ret
                # if not, we need to update it
                if 'ret' in state.keys():
                    rets[state['ret']] = state
    traces = {}
    trace_num = 0

    for ret, info in rets.items():


        t_ret = ret
        for i in statelogs:

            for state in statelogs[i]:

                if state['func'] in starts:

                    trace = {}
                    trace[state['func']] = {
                        'args': state['args'], 'ret': state['ret']}
                elif t_ret == state['args'][0] and state['func'] not in ends:
                    trace[state['func']] = {
                        'args': state['args'], 'ret': state['ret']}
                    t_ret = state['ret'] if state['ret'] else t_ret
                elif state['func'] in ends and t_ret == state['args'][0]:

                    trace[state['func']] = {
                        'args': state['args'], 'ret': state['ret']}
                    t_ret = ret

                    dup = False
                    for k, v in traces.items():
                        if trace == v:
                            dup = True
                    if not dup:
                        req = None
                        for key in trace.keys():
                            if key in conn:
                                req = f"{trace[key]['args'][1]}:{trace[key]['args'][2]}"
                            elif key in o_req:
                                req = f"{trace[key]['args'][1]} {req}{trace[key]['args'][2]}"
                        if req:
                            trace['req'] = req
                        traces[trace_num] = trace
                        trace_num += 1
    return traces

def coverage():

    d = 's2e-last'
    files = os.listdir(d)
    files.sort()
    covered = {}
    for f in [a for a in files if 'tbcoverage' in a]:
        with open(d+'/'+f) as json_f:
            cover = json.load(json_f)
            p = f.split(".")[0].split("-")[-1]
            covered[p] = cover[list(cover.keys())[0]]
    return covered


def main(inlog, outlog):
    lines = []
    with open(inlog, 'r') as f:
        for line in f:
            lines.append(line)
            parsed = parse_line(line)
            if parsed:
                jsonlog.append(parsed)

    with open('hlog.json', 'w') as f:
        json.dump(jsonlog, f, indent=True, sort_keys=True)

    for entry in jsonlog:
        stateid, funcname, args, ret = unpack(entry)

        if stateid not in statelogs:
            statelogs[stateid] = []

        statelogs[stateid].append(entry)

    with open('hlog_states.json', 'w') as f:
        json.dump(statelogs, f, indent=True, sort_keys=True)

    with open('hlog_states.txt', 'w') as f:
        for _, entries in sorted(statelogs.items()):
            for entry in entries:
                stateid, funcname, args, ret = unpack(entry)
                print(f"{stateid}\t{funcname}({', '.join(args)})", file=f)

    """
    for state, entries in sorted(statelogs.items()):
        lastconn = None
        for entry in entries:
            stateid, funcname, args, ret = unpack(entry)
            if funcname == 'InternetConnectA':
                lastconn = entry
            elif funcname == 'HttpOpenRequestA':
                url = f"{args[1]}\thttps://{lastconn['args'][1]}:{lastconn['args'][2]}{args[2]}"
                urls.add(url)

            elif funcname == 'WinHttpConnect':
                lastconn = entry
            elif funcname == 'WinHttpOpenRequest':
                url = f"{args[1]}\thttps://{lastconn['args'][1]}:{lastconn['args'][2]}{args[2]}"
                urls.add(url)
    """
    traces = extract_traces(statelogs)
    print(traces)

    c = coverage()
    import IPython
    IPython.embed()


if __name__ == '__main__':
    main('s2e-last/debug.txt', 'hlog.txt')
