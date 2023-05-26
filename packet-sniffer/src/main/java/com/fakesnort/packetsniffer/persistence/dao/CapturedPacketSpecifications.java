package com.fakesnort.packetsniffer.persistence.dao;

import org.springframework.data.jpa.domain.Specification;

import com.fakesnort.packetsniffer.persistence.model.CapturedPacket;

public class CapturedPacketSpecifications {
	
	public static Specification<CapturedPacket> isSeen(boolean seen){
	    return (root, query, criteriaBuilder) -> criteriaBuilder.equal(root.get("seen"), seen);
	}	

}
