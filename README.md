# MARSEA
Hiding in Plain Sight: An Empirical Study of Web Application Abuse in Malware

## Foreword
MARSEA is an extensible concolic analysis framework built on top of [S2E](https://github.com/S2E/s2e). To gain a general understanding of how concolic analysis works, please read the [S2E documentation](http://s2e.systems/docs/).

Before working with MARSEA, please read the accompanying paper to gain a thorough understanding of the tool and its potential extensions.

## Depolyment
For detailed deployment steps, refer to the README files for [s2e_win](s2e_win/README.md) and [s2e_linux](s2e_linux/README.md).

## Example Usage (DEMO)
This repository includes a malware sample named [Razy](example/0933a85ab3fec609bef86496b9c5e0140ff7e9c75b1d9219fc6202b551f4283b.zip). This section demonstrates how to use MARSEA to analyze it.

1. Copy your `custom-hook.dll` from the Windows machine to the [s2e_template](deploy/s2e_template) folder. For instructions on generating `custom-hook.dll`, refer to [s2e_win](s2e_win/README.md).
2. Unzip the [Razy](example/0933a85ab3fec609bef86496b9c5e0140ff7e9c75b1d9219fc6202b551f4283b.zip) sample.
3. Activate the S2E environment. For activation instructions, refer to [s2e_linux](s2e_linux/README.md).
4. Start the pipeline to analyze the unzipped file by executing `python pipeline.py -e [s2e_template] -s [sample_path]`, where `s2e_template` points to the absolute path of the [s2e_template](deploy/s2e_template) folder on your system, and `sample_path` points to the absolute path of the unzipped sample.
5. When the analysis is complete, you should see output similar to the following:
```python
Analysis Done!
{'JS': {'twitter.com/pidoras6': ['WinHttpReadData',
                                 'StrStr',
                                 'WinHttpCrackUrl']},
 'FU': {'virustotal.com': ['WinHttpSendRequest']}}
```
The demo video can be found [here](https://gtvault-my.sharepoint.com/:v:/g/personal/myao42_gatech_edu/EQOQ3DsCskdAt0fk8mTBxNkBdSj5BWLfglVehqnwqhMZwA?e=DAsYJ2)

