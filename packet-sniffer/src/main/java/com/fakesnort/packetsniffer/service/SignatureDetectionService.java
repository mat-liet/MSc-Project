package com.fakesnort.packetsniffer.service;

import org.pcap4j.packet.Packet;

public interface SignatureDetectionService {
	
	void handlePacket(Packet packet);

}
