import Utils
import Func
import sys
import re
import networkx as nx
from matplotlib.pylot as plt

def collect_funcs_with_args_and_tags(proj):

    funcs = set()

    cyfi_txts = curial.find_all_files(proj, "cyfi.txt", True)

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
                funcs.append(func)

    return funcs

def collect_all_funcs(proj):

    funcs = set()

    dbg_txts = curial.find_all_files(proj, "debug.txt", True)

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

    dbg_txts = curial.find_all_files(proj, "debug.txt", True)

    for dbg in dbg_text:
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
            tag_graph.add_edge(tag_out_name)

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
                f.write("ret: "+str(ret))

            f.write("\n")

def deump_all_funcs(funcs):
    with open('all_funcs', 'w') as f:
        for func in funcs:
            if not func.name:
                continue

            f.write(func.module+": "+func.name+"\n")

def dump_all_modules(modules):
    with open('all_modules', 'w') as f:
        for module in modules:
            f.write(module+"\n")


def dump_tag_grpah(tag_graph):
    nx.draw(tag_graph, with_labels=True)
    plt.savefig('tag_graph', dpi=300, bbox_inches='tight')
    plt.show()

if __name__ == "__main__":
    import ipdb
    ipdb.set_trace()
    proj = sys.argv[1]

    funcs_with_args_tags = collect_funcs_with_args_and_tags(proj)

    dump_funcs_with_args(funcs_with_args_tags)

    all_funcs = collect_all_funcs(proj)

    dump_all_funcs(all_funcs)

    all_modules = collect_all_loaded_modules(proj)

    dump_all_modules(all_modules)

    tag_graph = generate_tag_grpah(funcs_with_args_tag)

    dump_tag_graph(tag_graph)
