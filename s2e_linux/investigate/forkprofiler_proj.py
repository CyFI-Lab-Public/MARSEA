# Utilize forkprofiler_mp.py to analyze multi project results
import multiprocessing as mp
from pathlib import Path
import json
import forkprofiler_mp as fp
import shutil

PROJS_JSON = "/home/cyfi/lab/s2e_pwa_post/investigate/forkprofiler/all_proj.json"
REMOTE_PATH = "/mnt/cacee-netskope/dga_ls_run_fp"
LOCAL_S2E_PROJ_FOLDER = "/home/cyfi/s2e/projects/"

def handle_proj(remote_proj_path):
    proj_name = Path(remote_proj_path).stem

    try:
        shutil.copytree(remote_proj_path, LOCAL_S2E_PROJ_FOLDER+proj_name, ignore=shutil.ignore_patterns("guestfs"))
    except:
        pass

    fp.analyze_execution_trace(LOCAL_S2E_PROJ_FOLDER+proj_name, remote_path=REMOTE_PATH)

    return


def main():

    with open(PROJ_JSON) as f:
        projs = json.load(f)

    pool = mp.Pool(processes=mp.cpu_count(), maxtaskperchild=1000)
    results = list(
            tqdm.tqdm(
                pool.imap_unordered(
                    handle_proj, projs), total=len(projs)))
    pool.close()
    pool.join()

    return

if __name__ == "__main__":
    main()
