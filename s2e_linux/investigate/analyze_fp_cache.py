from pathlib import Path
import pickle
import forkprofiler_mp as fp

CACHE_FOLDER = "/mnt/cacee-netskope/forkprofiler/02-03-2022"

def combine_proj_results(fp_res):

    res = {}

    for proj, funcs in fp_res.items():
        all_count = sum(funcs.values())
        for func, count in funcs.items():
            if not func in res:
                res[func] = 0
            res[func] += count

    return dict(sorted(res.items(), key=lambda item: item[1], reverse=True))

def get_cache_result():
    res = []

    fd = Path(CACHE_FOLDER)
    to_folders = [fd]

    while to_folders:
        to_go = to_folders.pop()

        for item in to_go.iterdir():
            if item.is_dir():
                to_folders.append(item)

            else:
                res.append(item)

    return res

def find_proj_from_func(func_name, analyze_res):

    res = []

    for proj, funcs in analyze_res.items():
        if func_name in list(funcs.keys()):
            res.append(proj)

    return res

def main():
    fp_results = get_cache_result()

    if not fp_results:
        return

    analyze_results = {}

    for each_fp_res_path in fp_results:
        proj = Path(each_fp_res_path).parent.stem
        with open(each_fp_res_path, 'rb') as f:
            try:
                fp_res = pickle.load(f)
            except Exception as e:
                print(str(e))
                continue
        analyze_res = fp.analyze_record(fp_res)

        analyze_results[proj] = analyze_res

    inte_res = combine_proj_results(analyze_results)

    import ipdb
    ipdb.set_trace()

if __name__ == '__main__':
    main()
