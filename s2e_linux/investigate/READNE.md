To use `forkprofiler`, run command `s2e execution_trace -pp proj_name` to generate execution_trace.json file in s2e-last folder.
Then run `python forkprofiler [path to s2e-last]`
Once finish analyzing, it will invoke `ipdb` and users can run function `analyze_record()` to analyze `RECORD` to see generated states for different functions.
