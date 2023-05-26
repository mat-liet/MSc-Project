Project for MSc Computer Science at University of Birmingham.

Implementing a Network Intrusion Detection System using Pcap4J. 

Main objectives are:
1) Capture packets from whole network.
2) Check for port scans e.g. XMAS scan, FIN scan, NULL scan etc.
3) Signature search engine. Detects known signatures of intrusion attacks. 
3) Alert and logging system.

Dependencies for Pcap4J library are listed below but can also be found on their github page: https://github.com/kaitoy/pcap4j

The original MSC-Project is available in the mainPcap folder.

I have started to work on a new updated version of the project which adds Spring, Flyway, RabbitMQ, JPA to the project.
This new version is available in the packet-sniffer folder.
