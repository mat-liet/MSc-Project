package com.fakesnort.packetsniffer.service.impl;

import static com.fakesnort.packetsniffer.persistence.dao.CapturedPacketSpecifications.isSeen;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.fakesnort.packetsniffer.persistence.dao.CapturedPacketDao;
import com.fakesnort.packetsniffer.persistence.model.CapturedPacket;
import com.fakesnort.packetsniffer.service.CapturedPacketService;

@Service
public class CapturedPacketServiceImpl implements CapturedPacketService {
	
	@Autowired
	private CapturedPacketDao capturedPacketDao;

	@Override
	public CapturedPacket save(CapturedPacket packet) {
		return capturedPacketDao.save(packet);
	}

	@Override
	public List<CapturedPacket> getUnseenList() {
		return capturedPacketDao.findAll(isSeen(false));
	}

	@Override
	public List<CapturedPacket> findAll() {
		return capturedPacketDao.findAll();
	}

}
