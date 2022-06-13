#!/bin/bash
set -x
sudo apt-get -y install git gcc python3 python3-dev python3-venv wget curl

s2e_path=$(realpath $1)

cd $s2e_path

if [ ! -f "en_windows_7_professional_with_sp1_x86_dvd_u_677056.iso" ]; then
  curl -LOJR https://gatech.box.com/shared/static/etaefjaf7i6d5c0fh51dbg679dtdb1xb.iso
fi

if [ ! -f "win_apps.zip" ]; then
  curl -LOJR https://gatech.box.com/shared/static/n7pvq7t8v9v1zwe0cm7clsz6a5e8e9h1.zip
fi

if [ ! -d "cyfi-s2e" ]; then
  mkdir cyfi-s2e
  cd cyfi-s2e
  git clone https://github.gatech.edu/cyfi/s2e.git
  cd ..
fi

if [ ! -d "s2e-env" ]; then
    git clone https://github.com/s2e/s2e-env.git
    cd s2e-env
    git checkout 97727c4ca8549ce02d8529692f673a86e4763607
    cd ..
    # Hijack the init.py of s2e-env
    cp cyfi-s2e/s2e/back_compatible/init.py ./s2e-env/s2e_env/commands/init.py
    cp cyfi-s2e/s2e/back_compatible/default.xml .
    cp cyfi-s2e/s2e/back_compatible/determine_clang_binary_suffix.py .
fi

cd s2e-env
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip

pip install .

cd ..
if [ ! -d "s2e" ]; then
  s2e init s2e
fi

mkdir -p "$s2e_path/s2e/images/.tmp-output"
unzip win_apps.zip -d "$s2e_path/s2e/images/.tmp-output"

source ./s2e/s2e_activate

# Overwrite the origianl s2e
cp -r cyfi-s2e/s2e/s2e_linux/s2e/. ./s2e/source/s2e/
s2e build

sudo usermod -a -G docker $(whoami)
sudo chmod ugo+r /boot/vmlinu*
sudo usermod -a -G kvm $(whoami)

if [ ! -d "$s2e_path/s2e/images/windows-7sp1pro-i386" ]
then
  sudo su -l $USER -c "cd $s2e_path; . ./s2e-env/venv/bin/activate; source ./s2e/s2e_activate; s2e image_build --iso-dir . windows-7sp1pro-i386;"
fi
