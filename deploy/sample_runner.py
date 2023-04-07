# The script used to run one sample using S2E
import os
from pathlib import Path
import subprocess
import shutil
import getpass
import psutil
import json

# S2E env path
S2EDIR = os.environ['S2EDIR']

# Copy the necessary files from S2E_ENV_PATH to proj_folder
def copy_env_files(proj_folder, s2e_env_path, dll):

    if dll:
        # copy bootstrap_dll.sh
        env_bootstrap = Path(s2e_env_path)/"bootstrap_dll.sh"
        bs_path = Path(proj_folder)/"bootstrap.sh"
        shutil.copy(str(env_bootstrap), str(bs_path))

        # copy s2e-config.lua
        env_lua = Path(s2e_env_path)/"s2e-config_dll.lua"
        lua_path = Path(proj_folder)/"s2e-config.lua"
        shutil.copy(str(env_lua), str(lua_path))

    else:
        # copy bootstrap.sh
        env_bootstrap = Path(s2e_env_path)/"bootstrap.sh"
        bs_path = Path(proj_folder)/"bootstrap.sh"
        shutil.copy(str(env_bootstrap), str(bs_path))

        # copy s2e-config.lua
        env_lua = Path(s2e_env_path)/"s2e-config.lua"
        lua_path = Path(proj_folder)/"s2e-config.lua"
        shutil.copy(str(env_lua), str(lua_path))

    # Copy custom-hook.dll
    env_hook = Path(s2e_env_path)/"custom-hook.dll"
    hook_path = Path(proj_folder)/"custom-hook.dll"
    shutil.copy(str(env_hook), str(hook_path))

    # copy EasyHook32.dll
    env_eh32 = Path(s2e_env_path)/"EasyHook32.dll"
    eh32_path = Path(proj_folder)/"EasyHook32.dll"
    shutil.copy(str(env_eh32), str(eh32_path))

    # Copy launch-s2e.sh
    env_launch = Path(s2e_env_path)/"launch-s2e.sh"
    launch_path = Path(proj_folder)/"launch-s2e.sh"
    shutil.copy(str(env_launch), str(launch_path))

    # Copy malware-inject.exe
    env_inject = Path(s2e_env_path)/"malware-inject.exe"
    inject_path = Path(proj_folder)/"malware-inject.exe"
    shutil.copy(str(env_inject), str(inject_path))

    return True

# Prepare bootstrap.sh by replacing the keyword (replace) with the target name
def prepare_dll_bootstrap(proj_folder, target, export_func, symb_args):
    bs_path = Path(proj_folder)/"bootstrap.sh"
    cmd = "sed -i 's/{dllname}/"+target+"/g' "+str(bs_path)
    os.system(cmd)
    cmd = "sed -i 's/{exportFuncName}/"+export_func+"/g' "+str(bs_path)
    os.system(cmd)
    if symb_args:
        cmd = "sed -i 's/{symbArgs}/"+"--symbArgs"+"/g' "+str(bs_path)
        os.system(cmd)
    else:
        cmd = "sed -i 's/{symbArgs}/"+"--noSymbArgs"+"/g' "+str(bs_path)
        os.system(cmd)

    return True

def prepare_exe_bootstrap(proj_folder, target):
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
    # Replace the {S2EDIR} with the set system variable
    s2e_dir = os.environ.get('S2EDIR')
    if s2e_dir is None:
        print("S2EDIR is not set")
        return False
    cmd = "sed -i 's!{S2EDIR}!"+s2e_dir+"!g' "+str(lua_path)
    os.system(cmd)
    return True

def get_cyfi_time(proj_folder):
    launch_path = Path(proj_folder)/"launch-s2e.sh"
    content = launch_path.open('r').readlines()
    cyfitime = content[2].strip().split()[-2] + content[2].strip().split()[-1]
    return cyfitime

def prepare_launch(proj_folder, target, cyfitime):
    launch_path = Path(proj_folder)/"launch-s2e.sh"
    cmd = "sed -i 's!{cyfitime}!"+cyfitime+"!g' "+str(launch_path)
    os.system(cmd)
    cmd = "sed -i 's!{cyfitarget}!"+target+"!g' "+str(launch_path)
    os.system(cmd)
    cmd = "sed -i 's!{cyfiuser}!"+getpass.getuser()+"!g' "+str(launch_path)
    os.system(cmd)
    cmd = "sed -i 's!{cyfimp}!"+str(1)+"!g' "+str(launch_path)
    os.system(cmd)
    # Replace the {S2EDIR} with the set system variable
    s2e_dir = os.environ.get('S2EDIR')
    if s2e_dir is None:
        print("S2EDIR is not set")
        return False
    cmd = "sed -i 's!{S2EDIR}!"+s2e_dir+"!g' "+str(launch_path)
    os.system(cmd)
    return True
    

# Run the sample
def run(sample_path, template_path, export_func=None, symb_args=False, timeout=1500, execute=True):

    sample_path = Path(sample_path)

    # Run the sample using S2E
    proj_folder = None

    # If the sample is dll
    if export_func:
        # Get the path to myrundll32.exe in the template_folder
        my_rundll = Path(template_path)/'myrundll32.exe'

        if not my_rundll.exists():
            return None

        # Predict the project folder path
        proj_folder = Path(S2EDIR)/'projects'/(Path(sample_path).stem+'_'+export_func)

        # Create the project using S2E with the arbirtary name
        p = subprocess.Popen(['s2e', 'new_project', '-i', 'windows-7sp1pro-i386', str(my_rundll), '-n', str(Path(sample_path).stem)+'_'+export_func], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p.wait()

        if not proj_folder.exists():
            return None

        # Copy the target dll into the project folder
        shutil.copy(str(sample_path), str(proj_folder))

        os.chdir(str(proj_folder))

        # Copy the env files to the project folder
        copy_env_files(str(proj_folder), template_path, True)

        # Prepare the bootstrap.sh file
        prepare_dll_bootstrap(str(proj_folder), Path(sample_path).name, export_func, symb_args)


    else:
        proj_folder = Path(S2EDIR)/'projects'/(Path(sample_path).stem)

        p = subprocess.Popen(['s2e', 'new_project', '-i', 'windows-7sp1pro-i386', str(sample_path), '-n', str(Path(sample_path).stem)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p.wait()

        if not proj_folder.exists():
            return None

        os.chdir(str(proj_folder))

        # Copy the env files to the project folder
        copy_env_files(str(proj_folder), template_path, False)

        # Prepare the bootstrap.sh file
        prepare_exe_bootstrap(str(proj_folder), sample_path.name)

    
    # Since we will overwrite the launch-s2e.sh, capture the timestamp from it first (cyfitime)
    cyfitime = get_cyfi_time(str(proj_folder))

    # Prepare other files
    prepare_lua(str(proj_folder), sample_path.name)

    # Prepare the launch-s2e.sh file
    qemu_name = sample_path.name.replace('.', '')
    prepare_launch(str(proj_folder), qemu_name, cyfitime)

    # See if the users want to fire the project or not
    if not execute:
        return proj_folder

    # Run the launch script
    run_script = proj_folder/'launch-s2e.sh'
    p_s2e = subprocess.Popen([str(run_script)], shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    js = fu = False
    js_target = fu_target = ""

    while True:
        output = p_s2e.stdout.readline().decode('utf-8')

        if p_s2e.poll() is not None:
            break

        if output:
            
            if '/vtapi/v2/file/scan' in output:
                fu = True
                fu_target = 'virustotal.com'

            if 'twitter.com' in output:
                js_target = 'twitter.com/pidoras6'

            if 'WinHttpCrackUrl' in output and 'tag_in:CyFi' in output:
                js = True

            print(output.strip())

            if fu and js:
                break
    
    print('Analysis Done!')

    p_s2e.kill()

    try:

        for p in psutil.process_iter():
            if 'qemu-system' in p.name() and qemu_name in p.cmdline():
                p.kill()

    except:
        pass

    result_list = {}

    if js and fu:
        result_list = {'JS': {js_target: ["WinHttpReadData", "StrStr", "WinHttpCrackUrl"]}, 'FU': {fu_target: ["WinHttpSendRequest"]}}

        json_str = json.dumps(result_list, indent=4)

        RED = '\033[91m'

        print(RED + json_str + "\033[0m")

    return proj_folder
