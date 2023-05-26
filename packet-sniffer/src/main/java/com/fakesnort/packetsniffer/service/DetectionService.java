package com.fakesnort.packetsniffer.service;

import org.pcap4j.packet.Packet;

public interface DetectionService {
	
	void handlePacket(Packet packet);

}
