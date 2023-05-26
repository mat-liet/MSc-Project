package com.fakesnort.packetsniffer.service;

import java.util.List;

import com.fakesnort.packetsniffer.persistence.model.CapturedPacket;

public interface CapturedPacketService {
	
	List<CapturedPacket> findAll();
	
	CapturedPacket save(CapturedPacket packet);
	
	List<CapturedPacket> getUnseenList();

}
