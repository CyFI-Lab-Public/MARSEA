# Utilize forkprofiler_mp.py to analyze multi project results
import multiprocessing as mp
from pathlib import Path
import json
import forkprofiler_mp as fp
import shutil
import tqdm

PROJS_JSON = "all_proj.json"
REMOTE_PATH = "/mnt/cacee-netskope/forkprofiler/02-03-2022"
LOCAL_S2E_PROJ_FOLDER = "/home/cyfi/s2e/projects/"

def du(proj_fd):
    import subprocess
    return float(subprocess.check_output(['du','-sm', proj_fd]).split()[0].decode('utf-8'))

def handle_proj(remote_proj_path):

    res = []

    proj_name = Path(remote_proj_path).stem

    try:
        proj_size = du(remote_proj_path)
        if proj_size > 600:
            return []
    except Exception as e:
        print(str(e))
        return []

    try:
        shutil.copytree(remote_proj_path, LOCAL_S2E_PROJ_FOLDER+proj_name, ignore=shutil.ignore_patterns("guestfs"))
    except:
        pass

    try:
        res = fp.analyze_execution_trace(LOCAL_S2E_PROJ_FOLDER+proj_name, remote_path=REMOTE_PATH)
    except Exception as e:
        print(str(e))
        pass

    try:
        shutil.rmtree(LOCAL_S2E_PROJ_FOLDER+proj_name)
    except:
        pass

    return res

def main():

    final_result = {}

    with open(PROJS_JSON) as f:
        projs = json.load(f)

    import ipdb
    ipdb.set_trace()

    for proj in projs:
        res = handle_proj(proj)

    proj_res = fp.analyze_record(res)

    for funcName, count in proj_res.items():
        if not funcName in final_result:
            final_result[funcName] = 0
        final_result[funcName] += count


#    pool = mp.Pool(processes=mp.cpu_count(), maxtasksperchild=1000)
#    results = list(
#            tqdm.tqdm(
#                pool.imap_unordered(
#                    handle_proj, projs), total=len(projs)))
#    pool.close()
#    pool.join()

    import ipdb
    ipdb.set_trace()

    return

if __name__ == "__main__":
    main()
