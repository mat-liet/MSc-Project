package com.fakesnort.packetsniffer.service;

import org.pcap4j.packet.Packet;

public interface PortScanService {
	
	void handlePacket(Packet packet);

}
