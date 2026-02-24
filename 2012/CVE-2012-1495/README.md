# CVE-2012-1495-Webcalendar-
Prerequis : MAchine Kali linux ou Parrot Os 
1- Cloner le repository 

2- extraire l'archive "webcalendar"

3- Creer le container docker et le lancer à l'aide des commandes :

docker build -t webcalendar .
docker run -d -p 80:80 webcalendar

4- Sur votre machine kali, lancez metasploit et cherchez l'exploit puis le lancer.(se referer au rapport )
