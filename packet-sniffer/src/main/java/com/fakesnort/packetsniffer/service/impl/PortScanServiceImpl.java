package com.fakesnort.packetsniffer.service.impl;


import org.pcap4j.packet.AbstractPacket;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.namednumber.IpNumber;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.fakesnort.packetsniffer.amqp.producer.DatabaseProducer;
import com.fakesnort.packetsniffer.persistence.model.CapturedPacket;
import com.fakesnort.packetsniffer.service.Capture;
import com.fakesnort.packetsniffer.service.PortScanService;

/**
 * This class checks each packet for certain flags to be turned on.
 * If it detects a port scan, it will add it to the database insertion queue.
 * @author Matej Lietava
 * @version 2020-08-01
 */
@Service
public class PortScanServiceImpl implements PortScanService {
	
	@Autowired
	private DatabaseProducer databaseProducer;

    private final String XMAS_SCAN_WARNING = "XMAS SCAN DETECTED";

    private final String FIN_SCAN_WARNING = "FIN SCAN DETECTED";

    private final String NULL_SCAN_WARNING = "NULL SCAN DETECTED";

    /**
     * Checks for XMAS, FIN, or NULL scan.
     */
    @Override
    public void handlePacket(Packet packet) {
        // System.out.println("Port scan detecter on [" + Capture.getIDPacket(packet) + "]");
        if (isXmasScan(packet)) {
            int id = 0;
            int packetId = Capture.getIDPacket(packet);
            String msg = XMAS_SCAN_WARNING;
            String packetString = packet.get(AbstractPacket.class).toString();
            CapturedPacket portscanPacket = new CapturedPacket(id, packetId, msg, packetString);
            databaseProducer.sendMessage(portscanPacket);
        } else if (isFinScan(packet)) {
            int id = 0;
            int packetId = Capture.getIDPacket(packet);
            String msg = FIN_SCAN_WARNING;
            String packetString = packet.get(AbstractPacket.class).toString();
            CapturedPacket portscanPacket = new CapturedPacket(id, packetId, msg, packetString);
            databaseProducer.sendMessage(portscanPacket);
        } else if (isNullScan(packet)) {        
            int id = 0;
            int packetId = Capture.getIDPacket(packet);
            String msg = NULL_SCAN_WARNING;
            String packetString = packet.get(AbstractPacket.class).toString();
            CapturedPacket portscanPacket = new CapturedPacket(id, packetId, msg, packetString);
            databaseProducer.sendMessage(portscanPacket);
        }
        
    }

    /**
     * Helper method which checks if it is an XMAS scan. If URG, PSH, FIN packet turned on.
     * @param packet the packet being checked.
     * @return true if all 3 flags turned on or false if they are not.
     */
    private boolean isXmasScan(Packet packet) {
        if (isTcp(packet)) {
            return (getUrg(packet) && getPsh(packet) && getFin(packet));
        } else {
            return false;
        }
    }

    /**
     * Helper method which checks if it is an NULL scan. If all flags turned off.
     * @param packet the packet being checked.
     * @return true if all flags turned off or false if they are. 
     */
    private boolean isNullScan(Packet packet) {
        if (isTcp(packet)) {
            return (!getSyn(packet) && !getAck(packet) && !getRst(packet) && !getUrg(packet) && !getPsh(packet) && !getFin(packet));
        } else {
            return false;
        }
    }

    /**
     * Helper method which checks if it is an FIN scan. If FIN on and all others off.
     * @param packet the packet being checked.
     * @return true if FIN scan turned on.
     */
    private boolean isFinScan(Packet packet) {
        if (isTcp(packet)) {
            return (!getSyn(packet) && !getAck(packet) && !getRst(packet) && !getUrg(packet) && !getPsh(packet) && getFin(packet));
        } else {
            return false;
        }
    }

    /**
     * Checks if packet is a TCP packet.
     * @param packet the packet being checked.
     * @return true if TCP, false if not.
     */
    private boolean isTcp(Packet packet) {
    	if (packet.get(IpPacket.class) != null) {
    		return (packet.get(IpPacket.class).getHeader().getProtocol() == IpNumber.TCP);
    	}
        return false;
    }

    /**
     * Gets SYN flag.
     * @param packet packet being checked.
     * @return true if SYN is on and false if not.
     */
    private boolean getSyn(Packet packet) {
        return packet.get(TcpPacket.class).getHeader().getSyn();
    }

    /**
     * Gets ACK flag.
     * @param packet packet being checked.
     * @return true if ACK is on and false if not.
     */
    private boolean getAck(Packet packet) {
        return packet.get(TcpPacket.class).getHeader().getAck();
    }

    /**
     * Gets RST flag.
     * @param packet packet being checked.
     * @return true if RST is on and false if not.
     */
    private boolean getRst(Packet packet) {
        return packet.get(TcpPacket.class).getHeader().getRst();
    }

    /**
     * Gets URG flag.
     * @param packet packet being checked.
     * @return true if URG is on and false if not.
     */
    private boolean getUrg(Packet packet) {
        return packet.get(TcpPacket.class).getHeader().getUrg();
    }

    /**
     * Gets PSH flag.
     * @param packet packet being checked.
     * @return true if PSH is on and false if not.
     */
    private boolean getPsh(Packet packet) {
        return packet.get(TcpPacket.class).getHeader().getPsh();
    }

    /**
     * Gets FIN flag.
     * @param packet packet being checked.
     * @return true if FIN is on and false if not.
     */
    private boolean getFin(Packet packet) {
        return packet.get(TcpPacket.class).getHeader().getFin();
    }
    
}