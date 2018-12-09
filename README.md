# Alarmer
Analyzing a live stream or set of network packets for incidents

The tool analyzes the following incidents either on a `live network` or a given <code>.pcap</code> file:
  1. [NULL](https://www.plixer.com/blog/scrutinizer/the-null-scan-youre-being-watched/) scan
  2. [FIN](https://www.plixer.com/blog/general/what-is-a-fin-port-scan-how-does-it-work/) scan
  3. [Xmas](https://www.plixer.com/blog/detecting-malware/understanding-xmas-scans/) scan
  4. Usernames and passwords sent in-the-clear via HTTP Basic Authentication
  5. Usernames and passwords sent in-the-clear via FTP
  6. [Nikto](https://en.wikipedia.org/wiki/Nikto_Web_Scanner) scan

## Preliminaries:
- This program is written using the python version 3.x
- scapy is used
- pcapy should be present to work in conjunction with scapy
- It is preferrable to run this program inside Kali Linux.

## Usage

### Installation
<code>$ apt-get install python-pcapy</code><br>
Scapy and Python 2.7 are installed on Kali Linux.

### Running Tool in the system:
The tool has three command line arguments:

```
-i INTERFACE: Sniff on a specified network interface
-r PCAPFILE: Read in a PCAP file
-h: Display message on how to use tool
```

Go into the following directory:
```console
$ cd /path-to-repository/src/
```

Run the program:<br>

  <em>On a PCAP:</em>
  ```console
  $ python alarm.py -r ./SampleData/[any pcap file present in this directory].pcap
  ```
  <br>
  
  <em>On a live Network Interface:</em>
  ```console
  $ python alarm.py -i [NETWORK INTERFACE]
  ```

<img src="https://github.com/sheheryarnaveed/Live-Temperature-Reporting-ChatBot/blob/master/IMG_20180110_142712.png" width="320" height="550">

![Image1](https://cloud.githubusercontent.com/assets/173/5562290/48e24654-8ddf-11e4-8fe7-735b0ce3a0d3.png)
