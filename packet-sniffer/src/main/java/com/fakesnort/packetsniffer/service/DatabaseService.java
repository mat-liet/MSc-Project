package com.fakesnort.packetsniffer.service;

import com.fakesnort.packetsniffer.persistence.model.CapturedPacket;

public interface DatabaseService {

	void handlePacket(CapturedPacket packet);

}
