class Func():

    def __init__(self):
        self.name = ""
        self.args = []
        self.ret = None
        self.tag_in = None
        self.tag_out = None

        self.call_addr = None
        self.module = None

    def __hash__(self):
        all_str = str(self.name) + str(self.args) + str(self.ret)

        return hash(all_str)

    def __eq__(self, other):
        return self.name == other.name and self.args == other.args and self.ret == other.ret

def analyze_line(line):

    if not '[W]' in line:
        return None

    func = Func()

    func_info = line.split('[W]')[1].strip()

    param_info_left = func_info.find("(") + 1
    param_info_right = func_info.rfind(")")
    param_info = func_info[param_info_left:param_info_right]
    params = [x.strip() for x in param_info.split('[|]')]

    func.name = func_info[:param_info_left-1].strip()
    func.args = params

    if param_info_right + 1 < len(func_info):
        more_info = func_info[param_info_right+1:]
        infos = [x.strip() for x in more_info.split()]
        for info in infos:
            try:
                info_type, info_value = info.split(':')
            except:
                return func

            if info_type == "ret":
                func.ret = info_value

            elif info_type == "tag_in":
                func.tag_in = info_value

            elif info_type == "tag_out":
                func.tag_out = info_value

            else:
                print("Unsupported information in line: ", info_type)

    return func

def analyze_libcall_line(line, proj=""):

    if 'LibraryCallMonitor: '+proj in line:

        if "Could not get export name for address" in line:

            return None

        if "jumped to" in line:
            line = line.replace("jumped to", "jumpedto")

        try:
            # if it is s2e mp
            if line.split()[1] == "[Node":
                proj_addr = line.split()[7]
                call_addr = proj_addr.split(':')[1]
                dll_func_addr = line.split()[10]
                module = dll_func_addr.split('!')[0]
                func_name = dll_func_addr.split('!')[1].split(':')[0]

            else:
                proj_addr = line.split()[4]
                call_addr = proj_addr.split(':')[1]
                dll_func_addr = line.split()[7]
                module = dll_func_addr.split('!')[0]
                func_name = dll_func_addr.split('!')[1].split(':')[0]
        except:
            return None

        func = Func()

        func.name = func_name
        func.call_addr = call_addr
        func.module = module

        return func

    else:
        return None    
