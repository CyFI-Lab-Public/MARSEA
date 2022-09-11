# Used to generate all proj folder paths used to investigation

from pathlib import Path
import json

TOP_FOLDER = ["/mnt/cacee-netskope/curial_result/result/forkprofiler"]

def get_all_projs():
    res = []

    to_check = []
    to_check.extend(TOP_FOLDER)

    while to_check:
        go_to = Path(to_check.pop())
        
        print("Checking ", str(go_to))

        if go_to.is_dir():
            # Check the existence of launch-s2e.sh
            if (go_to/"launch-s2e.sh").exists():
                res.append(go_to)

            else:
                # Otherwise iterating that folder
                for each_item in go_to.iterdir():
                    if each_item.is_dir():
                        to_check.append(each_item)

    return res

def cache_all_projs_path(projs_path):

    with open("all_proj.json", "w") as f:
        json.dump([str(x) for x in projs_path], f)

    return True

if __name__ == "__main__":
    all_projs_path = get_all_projs()
    cache_all_projs_path(all_projs_path)
