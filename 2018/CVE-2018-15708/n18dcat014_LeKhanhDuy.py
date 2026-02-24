from scapy.all import sniff, TCP, IP
from datetime import datetime, date
from colorama import init, Fore


import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# Send Mail
sender_address = '' # Email Account
sender_pass = ''    # Email Password
receiver_address = ''   # Send Email Address
smtp_server = ''    # SMTP Server


count_1 = 0
count_2 = 0
count_3 = 0
count_4 = 0
count_5 = 0
count_atk = 0

attacker_ip = ''
attacker_port = []

victim_ip = ''
victim_port = []

RED = Fore.RED
RESET = Fore.RESET
GREEN = Fore.GREEN


def process(packet):
    global count_atk, count_1, count_2, count_3, count_4, count_5, attacker_ip, attacker_port, victim_ip, victim_port

    if packet.haslayer(TCP):
        try:
            src = packet[IP].src
            dst = packet[IP].dst

            sport = packet[TCP].sport
            dport = packet[TCP].dport
            flags = packet[TCP].flags
            window = packet[TCP].window

            if flags == 'S' and window == 64240:  # Attacker-> Victim
                count_1 = 1
                attacker_ip = src
                victim_ip = dst

                # check duplicate port Attacker
                if sport in attacker_port:
                    return
                else:
                    attacker_port.append(sport)

                # check duplicate port Victim
                if dport in victim_port:
                    return
                else:
                    victim_port.append(dport)

            if flags == 'SA' and window == 28960:  # Victim -> Attacker
                count_2 = 1

                # check duplicate port Attacker
                if dport in attacker_port:
                    return
                else:
                    attacker_port.append(dport)

                # check duplicate port Victim
                if sport in victim_port:
                    return
                else:
                    victim_port.append(sport)

            if flags == 'S' and window == 29200:  # Attacker-> Victim
                count_3 = 1

                # check duplicate port Attacker
                if sport in attacker_port:
                    return
                else:
                    attacker_port.append(sport)

                # check duplicate port Victim
                if dport in victim_port:
                    return
                else:
                    victim_port.append(dport)

            if flags == 'SA' and window == 65160:  # Victim -> Attacker
                count_4 = 1

                # check duplicate port Attacker
                if dport in attacker_port:
                    return
                else:
                    attacker_port.append(dport)

                # check duplicate port Victim
                if sport in victim_port:
                    return
                else:
                    victim_port.append(sport)

            if flags == 'A' and window == 510:
                count_5 += 1

            if count_1 and count_2 and count_3 and count_4 and count_5 > 500:
                now = datetime.now()

                subject = 'Cảnh báo!! Bạn đang bị khai thác lỗ hổng CVE-2018-15708'

                print(
                    f'{RED}{subject}')

                print(f'{now} || {attacker_ip} -> {victim_ip} \n {RESET}')

                count_atk += 1
                while count_atk > 0:
                    s = str(now) + ' | ' + str(attacker_ip) + ' -> ' + \
                        str(victim_ip) + ' | ' + str(attacker_port) + \
                        ' -> ' + str(victim_port) + '\n'

                    saveToFile('n18dcat014_LeKhanhDuy.csv', s)
                    sendMail(subject, s)

                    count_atk -= 1

                count_1 = 0
                count_2 = 0
                count_3 = 0
                count_4 = 0
                count_5 = 0
                attacker_ip = ''
                attacker_port = []
                victim_ip = ''
                victim_port = []

        except IndexError:
            pass


def sendMail(subject, content):
    mail_content = content

    # sender_address
    # sender_pass
    # receiver_address
    # sender_address = 'duysupercellid@gmail.com'
    # sender_pass = 'lceuiotmytwxlkgo'
    # receiver_address = 'lkduy2602@gmail.com'

    message = MIMEMultipart()
    message['From'] = sender_address
    message['To'] = receiver_address
    message['Subject'] = subject

    message.attach(MIMEText(mail_content, 'plain'))

    session = smtplib.SMTP(smtp_server, 587)
    session.starttls()

    session.login(sender_address, sender_pass)
    text = message.as_string()
    session.sendmail(sender_address, receiver_address, text)
    session.quit()
    print(f'{GREEN}Đã gửi mail cảnh báo đến {receiver_address} \n')


def saveToFile(fileName, data):
    with open(fileName, 'a') as fileHandler:
        fileHandler.write(data)
        print(f'{GREEN}Đã lưu thông tin vào file {fileName}')


if __name__ == "__main__":
    # Sử dụng live capture
    sniff(store=False, prn=process, iface='VMware Network Adapter VMnet8')

    # Sử dụng file pcap để test
    # sniff(store=False, prn=process, offline='data_test.pcap')
