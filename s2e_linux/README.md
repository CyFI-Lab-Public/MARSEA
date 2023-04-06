# MARSEA Linux Deployment

## Recommended System
- Ubuntu 22.04 LTS
- Memory: 32GB
- Number of processors: 12
- Number of cores per processor: 1
- Disk space: 250GB

**Note**: The above recommendations are for system configurations. The setup should work for Ubuntu 18.04 LTS and later.

## Building
Since MARSEA is built on top of S2E, we need to install the S2E environment first.
Follow the S2E [documentation](http://s2e.systems/docs/s2e-env.html) up to, but not including, [building S2E](http://s2e.systems/docs/s2e-env.html#building-s2e).
Watch the building process in this [video tutorial](https://gtvault-my.sharepoint.com/:v:/g/personal/myao42_gatech_edu/EQIDZfKRrntLj9ZwzLl2j-0B3oAgE0zz0McjEaoCj33wAQ?e=lR99P8).

### MARSEA Customized Changes
MARSEA requires customized changes in S2E to work, including custom-developed plugins, exploration strategies, and more.
Overwrite the `s2e` folder in `$S2EDIR/source` with MARSEA's [s2e](s2e) folder.
Activate the S2E environment and get the path of `$S2EDIR` by running `echo $S2EDIR`.
Watch the video tutorial for this step [here](https://gtvault-my.sharepoint.com/:v:/g/personal/myao42_gatech_edu/EWW5QOB24ANJgQRUXl7vwcEBUC23NxBDPrqaNzBn3jevgQ?e=43C4Wh).

### Build the Toolset
Activate the S2E environment and run the command `s2e build` to build S2E.
Watch the video tutorial for this step [here](https://gtvault-my.sharepoint.com/:v:/g/personal/myao42_gatech_edu/EYxdwJ2Gwr5LhjH9g39hcLoB9mQUowRJyMoIs8Mrx8a8IQ?e=55haM3).

### Guest Installation
MARSEA executes the target in the guest system to isolate its behaviors from the host.
We need to install the guest operating system.
MARSEA currently supports Windows 7 i386. More recent Windows versions may work but have not been tested yet.
Follow these steps to build a Windows 7 i386 guest:

1. For remote access users using the command-line interface, create a [tmux](https://github.com/tmux/tmux) session first, as each step may take some time.
2. Download the official Windows 7 i386 guest ISO [here](https://gtvault-my.sharepoint.com/:u:/g/personal/myao42_gatech_edu/EY0XbpzpNKJPh1G4ZJj6acIBUGlvloZmr-kYvw8EL3NU0A?e=TeNfp9).
3. Verify the integrity of the downloaded ISO (md5:`0bff99c8310ba12a9136e3d23606f3d4`) and ensure the ISO's name is `en_windows_7_professional_with_sp1_x86_dvd_u_677056.iso`.
4. Activate the S2E environment and run `s2e image_build --iso-dir [/path/to/isos] windows-7sp1pro-i386`
The video of the these steps can be found [here](https://gtvault-my.sharepoint.com/:v:/g/personal/myao42_gatech_edu/Ee4nChum5DJGv7Nt34tjlzoBh7F1D0J8IaP9a0JqNFr3-Q?e=t9j5vg)
