import argparse
from tqdm import tqdm
import json
import os
import sample_runner as sr

def is_json(file_path):
    try:
        json.load(open(file_path))
    except ValueError as _:
        return False
    return True

if __name__ == "__main__":

    parser = argparse.ArgumentParser()

    parser.add_argument('-e', '--s2e-env', type=str, dest='s2eEnvPath')

    parser.add_argument('-s', '--sample', type=str, dest='samples')

    parser.add_argument('-o', '--res-folder', type=str, required=False, dest='resFolder', default=None)

    parser.add_argument('-t', '--time-out', type=int, dest='timeout', default=1500)

    parser.add_argument('--run', action='store_true')

    parser.add_argument('--no-run', dest='run', action='store_false')

    parser.add_argument('-symbArgs', '--symbArgs', type=bool, dest='symbArgs', default=False)

    parser.add_argument('-f', '--func', type=str, dest='func', default=None)

    args = parser.parse_args()

    # Check what type of sample passed to the launcher
    # If it is a folder, then we need to iterate over all files in the folder
    samples = []
    if os.path.isdir(args.samples):
        for file in os.listdir(args.samples):
            samples.append(os.path.join(args.samples, file))

    # If it is a json file, read the content in the samples
    elif os.path.isfile(args.samples):
        if is_json(args.samples):
            samples = json.load(open(args.samples))
        else:
            samples.append(args.samples)

    else:
        pass

    # Now fire each sample using s2e
    for sample in tqdm(samples, desc="Launching S2E"):
        proj_folder = sr.run(sample, args.s2eEnvPath, args.func, args.symbArgs, args.timeout, args.run)

        # If defined result folder, move the project folder away
        if args.resFolder and proj_folder:
            os.rename(proj_folder, os.path.join(args.resFolder, os.path.basename(proj_folder)))
