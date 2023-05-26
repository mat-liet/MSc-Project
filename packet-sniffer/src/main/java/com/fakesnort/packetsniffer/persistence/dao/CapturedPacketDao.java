package com.fakesnort.packetsniffer.persistence.dao;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

import com.fakesnort.packetsniffer.persistence.model.CapturedPacket;

public interface CapturedPacketDao extends JpaRepository<CapturedPacket, Integer>, JpaSpecificationExecutor<CapturedPacket> {

}
