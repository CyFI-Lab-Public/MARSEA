from pathlib import Path
import os
import sys
import subprocess
import shutil
import pefile
import psutil
import getpass

script_path = Path( __file__ ).parent.absolute()

S2E_ENV_PATH = str(script_path/"s2e_template")

S2EDIR = os.getenv('S2EDIR')

TIMEOUT = 400

SAMPLE_PATH = sys.argv[1]

def list_export(sample_path):
    exported_funcs = []
    try:

        mype2 = pefile.PE(sample_path, fast_load=False)

        if mype2.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']].VirtualAddress != 0:
            mype2.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])

            if hasattr(mype2, 'DIRECTORY_ENTRY_EXPORT'):
                for exptab in mype2.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exptab.name is not None:
                        exported_funcs.append(exptab.name.decode('utf-8'))

    except:

        pass

    return exported_funcs

# Prepare bootstrap.sh by replacing the keyword (replace) with the target name
def prepare_bootstrap(proj_folder, target):
    bs_path = Path(proj_folder)/"bootstrap.sh"
    cmd = "sed -i 's/{replace}/"+target+"/g' "+str(bs_path)
    os.system(cmd)
    return True

def prepare_lua(proj_folder, target):
    lua_path = Path(proj_folder)/"s2e-config.lua"
    cmd = "sed -i 's!cyfipath!"+proj_folder+"!g' "+str(lua_path)
    os.system(cmd)
    cmd = "sed -i 's!cyfitarget!"+target+"!g' "+str(lua_path)
    os.system(cmd)
    cmd = "sed -i 's!cyfiuser!"+getpass.getuser()+"!g' "+str(lua_path)
    os.system(cmd)
    cmd = "sed -i 's!s2eenv!"+str(S2EDIR)+"!g' "+str(lua_path)
    os.system(cmd)
    return True

def prepare_launch(proj_folder, target, cyfitime):
    launch_path = Path(proj_folder)/"launch-s2e.sh"
    cmd = "sed -i 's!{cyfitime}!"+cyfitime+"!g' "+str(launch_path)
    os.system(cmd)
    cmd = "sed -i 's!{cyfitarget}!"+target+"!g' "+str(launch_path)
    os.system(cmd)
    cmd = "sed -i 's!{cyfiuser}!"+getpass.getuser()+"!g' "+str(launch_path)
    os.system(cmd)
    cmd = "sed -i 's!{cyfimp}!"+str(os.cpu_count())+"!g' "+str(launch_path)
    os.system(cmd)
    cmd = "sed -i 's!{s2eenv}!"+str(S2EDIR)+"!g' "+str(launch_path)
    os.system(cmd)
    return True

def get_all_files(folder_path):
    p = Path(folder_path)

    sub_folders = [p]

    files = []

    while len(sub_folders):
        now_dir = sub_folders.pop()

        for child in now_dir.iterdir():
            if child.is_dir():
                sub_folders.append(child)
            if child.is_file():
                files.append(child)

    return files

def get_cyfi_time(proj_folder):
    launch_path = Path(proj_folder)/"launch-s2e.sh"
    content = launch_path.open('r').readlines()
    cyfitime = content[2].strip().split()[-2] + content[2].strip().split()[-1]
    return cyfitime

# Copy the necessary files from S2E_ENV_PATH to proj_folder
def copy_env_files(proj_folder):
    env_files = get_all_files(S2E_ENV_PATH)
    for each_env_file in env_files:
        shutil.copy(str(each_env_file), proj_folder)

    return True

def main():
    sample = SAMPLE_PATH
    sample = Path(sample)
    
    try:
        exported_funcs = list_export(str(sample))

        if len(exported_funcs) > 0:
            print("NO SUPPORT FOR DLL FOR NOW")
            return

        proj_folder = Path(S2EDIR)/'projects'/sample.stem
        
        p = subprocess.Popen(['s2e', 'new_project', '-i', 'windows-7sp1pro-i386', str(sample)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p.wait()

        if not proj_folder.exists():
            print("CANNOT CREATE PROJ FOLDER")
            return

        old_path = os.getcwd()

        os.chdir(str(proj_folder))

        # Since we will overwrite the launch-s2e.sh, capture the timestamp from it first (cyfitime)
        cyfitime = get_cyfi_time(str(proj_folder))

        # Copy the env files to the project folder
        copy_env_files(str(proj_folder))

        # Prepare the bootstrap.sh file
        prepare_bootstrap(str(proj_folder), sample.name)

        # Prepare the s2e-config.lua file
        prepare_lua(str(proj_folder), sample.name)

        # Prepare the launch-s2e.sh file
        qemu_name = sample.name.replace('.', '')
        prepare_launch(str(proj_folder), qemu_name, cyfitime)

        # Run the launch script
        run_script = proj_folder/'launch-s2e.sh'
        p_s2e = subprocess.Popen([str(run_script)], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        # p_s2e = subprocess.Popen([str(run_script)], shell=True)

        # Wait for timeout
        try:
            _, errs = p_s2e.communicate(timeout=TIMEOUT)
            # p_s2e.wait(timeout=TIMEOUT)
            errs = errs.decode('utf-8')
            if 'Segmentation fault' in errs:
                fSegFault = proj_folder/"segFault"
                fSegFault.touch(exist_ok=True)

        except Exception as e:
            # Create a timeout flag file
            fTimeOut = proj_folder/"timeout"
            fTimeOut.touch(exist_ok=True)
            p_s2e.kill()

        # kill_qemu_by_name('qemu-system-i386', qemu_name)

        try:

            for p in psutil.process_iter():
                if 'qemu-system' in p.name():
                    p.kill()

        except:
            pass

        # Change the working directory back
        os.chdir(old_path)

    except Exception as e:
        print(str(e))
        traceback.print_exc()
        pass

if __name__ == "__main__":
    main()
