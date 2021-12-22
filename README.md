Description:
===========
This is a hacking tool that allows users to exploit code injection with ARP spoofing. <br>
For more information on how the attack works, see Documentation.pdf.

Instructions for Use: 
===========
1. for this tool, you need to install all the libraries from the dependencies file. 
2. run arp_spoofer.py with the appropriate command line parameters.
3. run code_injector.py with the appropriate command line parameters. 
4. now you can inject the code.

Dependencies:
============
1. This will only work on a Linux machine. <br>
2. You must have "libcap" installed

Example:
=======
Assume that:<br>
1. the network interface is eth0 :<br>
2. the IP of the victim is 192.168.1.16 :<br>
3. the code we want to inject is in the path ./injected.js :<br>

Then, to execute the attack, call the following commands:<br>
1. sudo python3 arp_spoofer.py --interface eth0 --ip 192.168.1.16 2. <br>
2. sudo python3 code_injector.py --file ./injected.js

Testing:
========
1. create a network in the virtual box
2. create 2 virtual machines in the virtual box, one of them with Linux connected to the previous network. 
3. download the code-injection-tool folder into the Linux virtual machine.
4. proceed as in the previous example.
5. try to connect to an http site from the victim machine.
