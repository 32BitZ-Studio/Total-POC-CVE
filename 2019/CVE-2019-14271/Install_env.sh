sudo apt-get update

sudo apt-get install -y python3-pip
sudo apt-get install -y docker.io
git clone https://github.com/Metarget/metarget.git
cd ./metarget
pip3 install -r requirements.txt
cp -r ./writeups_cnv/docker-cve-2019-14271/exp ../
sudo ./metarget cnv install cve-2019-14271
cd ..
chmod 777 ./exp/breakout

# Building the image
docker build -t 14271  ./exp