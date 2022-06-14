from pathlib import Path

def find_all_files(top_folder, file_name=None, s2e_last=False):
    res = []

    excludes = ["guestfs"]

    to_check = [Path(top_folder)]

    while to_check:
        to_go = to_check.pop()

        for item in to_go.iterdir():
            if item.is_dir() and not item.name in excludes:
                to_check.append(item)

            if item.is_file():
                if file_name is not None and item.name == file_name:
                    if s2e_last and "s2e-last" in str(item):
                        res.append(item)

                    if not s2e_last:
                        res.append(item)

                elif file_name is None:
                    if s2e_last and "s2e-last" in str(item):
                        res.append(item)
                    if not s2e_last:
                        res.append(item)

    return res

def reorganize(file_content):
    new_file_content = []

    def prob_next(ind, lines):

        while ind < len(lines):
            prob_line = lines[ind]
            if 'State' in prob_line or 'Vmi' in prob_line or 'KLEE: WARNING' in prob_line or 'LoadBalancing' in prob_line:
                return ind

            ind += 1

        return ind

    i = 0

    while i < len(file_content):
        line = file_content[i]

        if '[W]' in line:
            next_line_ind = prob_next(i+1, file_content)

            new_line = ''.join(file_content[i:next_line_ind]).replace("\n","")
            new_file_content.append(new_line)

            i = next_line_ind

        else:
            new_file_content.append(line)
            i += 1

    return new_file_content

def get_sample_name(proj_fd):
    proj_fd = Path(proj_fd)

    for item in proj_fd.iterdir():
        if item.name.startswith(proj_fd.name):
            return item.name

    return proj_fd.name

def get_func_name_from_tag(tag_name, trim=False):

    if tag_name.startswith("CyFi_"):
        funcName = tag_name.lstrip("CyFi_")[:-1]
        # Get rid of the digits at the end of funcName
        funcName = funcName.rstrip("0123456789")
    else:
        funcName = tag_name

    if not trim:
        return funcName
    else:
        funcName = funcName.rstrip("ExA")
        funcName = funcName.rstrip("ExW")
        funcName = funcName.rstrip("A")
        funcName = funcName.rstrip("W")

        return funcName
