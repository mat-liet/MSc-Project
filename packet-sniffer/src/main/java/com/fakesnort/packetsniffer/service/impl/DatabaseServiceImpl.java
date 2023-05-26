package com.fakesnort.packetsniffer.service.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.fakesnort.packetsniffer.persistence.model.CapturedPacket;
import com.fakesnort.packetsniffer.service.CapturedPacketService;
import com.fakesnort.packetsniffer.service.DatabaseService;

@Service
public class DatabaseServiceImpl implements DatabaseService {
	
	@Autowired
	private CapturedPacketService capturedPacketService;;

	@Override
	public void handlePacket(CapturedPacket packet) {
		capturedPacketService.save(packet);
	}

}
