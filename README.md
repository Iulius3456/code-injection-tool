Description:
===========
This is a hacking tool that allows users to exploit code injection with arp spoofing. <br>
For more information on how the attack works, see Documentation.pdf.

Instructions for Use: 
===========
1. for this tool, you need to install all the libraries from the dependencies file. 
 arp_spoofer.py with the appropriate command line parameters.
3. run code_injector.py with the appropriate command line parameters. 
4. now you can inject the code.

Dependencies:
============
This will only work on a Linux machine.
You must have "libcap" installed

Example:
=======
Assume that:<br>
1. the network interface is eth0 :<br>
2. the IP of the victim is 192.168.1.16 :<br>
3. the code we want to inject is in the path ./injected.js :<br>

Then, to execute the attack, call the following commands:
==========================================================
1. sudo python3 arp_spoofer.py --interface eth0 --ip 192.168.1.16 2. sudo python3 code_injector --file ./injected.js
