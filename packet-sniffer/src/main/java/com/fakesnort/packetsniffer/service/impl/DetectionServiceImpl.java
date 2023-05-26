package com.fakesnort.packetsniffer.service.impl;

import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.Packet;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.fakesnort.packetsniffer.service.DetectionService;
import com.fakesnort.packetsniffer.service.PortScanService;
import com.fakesnort.packetsniffer.service.SignatureDetectionService;

@Service
public class DetectionServiceImpl implements DetectionService {
	
	@Autowired
	private SignatureDetectionService sigDetectionService;
	
	@Autowired
	private PortScanService portScanService;

	@Override
	public void handlePacket(Packet packet) {
        if (!isNullPayload(packet)) {
        	sigDetectionService.handlePacket(packet);
        }
        // Check every packet for port scans
        portScanService.handlePacket(packet);
	}
	
	// Get data payload
    private boolean isNullPayload(Packet packet) {
        return (packet.get(IpPacket.class).getPayload().getPayload() == null);
    }

}
