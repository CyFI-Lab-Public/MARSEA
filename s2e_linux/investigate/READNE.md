1. To use `forkprofiler`, run command `s2e execution_trace -pp proj_name` to generate execution_trace.json file in s2e-last folder.

2. Then run `python forkprofiler.py [path to s2e-last]`

3. Once finish analyzing, it will invoke `ipdb` and users can run function `analyze_record()` to analyze `RECORD` to see generated states for different functions.

4. Function `get_line_number_from_func` accepts a function name and returns a list of line number in debug.txt file users can use to investigate further
