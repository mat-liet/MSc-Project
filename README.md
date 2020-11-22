Project for MSc Computer Science at University of Birmingham.

Implementing a Network Intrusion Detection System using Pcap4J. 

Main objectives are:
1) Capture packets from whole network.
2) Check for port scans e.g. XMAS scan, FIN scan, NULL scan etc.
3) Signature search engine. Detects known signatures of intrusion attacks. 
3) Alert and logging system.

Dependencies for Pcap4J library are listed below but can also be found on their github page: https://github.com/kaitoy/pcap4j

Pcap4j 1.1.0 or older needs Java 5.0+. Pcap4j 1.2.0 or newer needs Java 6.0+. And also a pcap native library (libpcap 1.0.0+, WinPcap 3.0+, or Npcap), jna, slf4j-api, and an implementation of logger for slf4j are required. I'm using the following libraries for the test.


- libpcap 1.1.1

- WinPcap 4.1.2

- jna 5.1.0

- slf4j-api 1.7.25

- logback-core 1.0.0
- logback-classic 1.0.0

All other dependencies are mentioned in the report.
 - Maven and PostgreSQL

Information on how to run the software is in the report.

By Matej Lietava
