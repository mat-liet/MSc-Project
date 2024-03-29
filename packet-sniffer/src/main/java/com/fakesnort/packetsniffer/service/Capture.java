package com.fakesnort.packetsniffer.service;


import java.sql.Timestamp;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import com.fakesnort.packetsniffer.amqp.producer.DetectionProducer;

/**
 * This class opens the infinite loop that captures packets and then either places them
 * into a fragment map (for defragmentation) or into the inspection queue (for signature detection).
 * @author Matej Lietava
 * @version 2020-08-01
 */
@Component
public class Capture implements ApplicationRunner {

    private static PcapHandle pcapHandle;

    private static Map<Integer, List<IpV4Packet>> fragments = new ConcurrentHashMap<Integer, List<IpV4Packet>>();

    private static Map<Integer, Packet> originalPackets = new ConcurrentHashMap<Integer, Packet>();

    private static Map<Integer, Timestamp> timeStampArrival = new ConcurrentHashMap<Integer, Timestamp>();

    @Autowired
    private DetectionProducer detectionProducer;
    
    private static boolean running;

    private static int MAX_SIZE = 0;

    /**
     * This method checks if it is a non fragmented packet, if it is, it will just be added to the
     * inspection queue. If it is fragmented, it will be added a list of fragments in a Map.
     */
    @Override
	public void run(ApplicationArguments args) throws Exception {
    	PcapNetworkInterface device;
		try {
			List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();
			device = allDevs.get(0);
			pcapHandle = device.openLive(65536, PromiscuousMode.PROMISCUOUS, 50);
		} catch (PcapNativeException e) {
			e.printStackTrace();
		}
        PacketListener listener = new PacketListener() {
            public void gotPacket(Packet packet) {
            	if (packet.get(IpPacket.class) != null) {
//                  if (!isNonFragmented(packet)) {
//                  if (fragments.containsKey(getIDPacket(packet))) {
//                      fragments.get(getIDPacket(packet)).add(packet.get(IpV4Packet.class));
//                  } else {
//                      ArrayList<IpV4Packet> list = new ArrayList<>();
//                      list.add(packet.get(IpV4Packet.class));
//                      fragments.put(getIDPacket(packet), list);
//                      timeStampArrival.put(getIDPacket(packet), pcapHandle.getTimestamp());
//                      originalPackets.put(getIDPacket(packet), packet);
//                  }
//              } else {
                  detectionProducer.sendMessage(packet);
//              }
            	}

            };
        };
        startLoop(listener);
		
	}

    /**
     * Start loop method.
     * @param listener
     */
    public void startLoop(PacketListener listener) {
        try {
            pcapHandle.loop(-1, listener);
            System.out.println("Capture started...");
        } catch (PcapNativeException | NotOpenException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            pcapHandle.close();
            System.out.println("Handle closed.");
            System.out.println("Loop broken.");
            running = false;
        }
    }

    /**
     * Getter for the pcapHandle.
     * @return the PcapHandle.
     */
    public static PcapHandle getHandle() {
        return pcapHandle;
    }

    /**
     * This method returns the identification number of the packet. as an int.
     * @param packet packet which contains the id
     * @return the id number as an int of the packet.
     */
    public static int getIDPacket(Packet packet) {
        return packet.get(IpV4Packet.class).getHeader().getIdentificationAsInt();
    }

    /**
     *  This method returns the fragment offset of the packet.index
     * @param packet 
     * @return the fragment offset of the packet.
     */
    public static int getOffset(Packet packet) {
        return packet.get(IpV4Packet.class).getHeader().getFragmentOffset();
    }

    /**
     * This method returns the total length of the packet as an int. 
     * @param packet
     * @return the total length of the packet.
     */
    public static int getTotalLength(Packet packet) {
        return packet.get(IpV4Packet.class).getHeader().getTotalLengthAsInt();
    }

    /**
     * The getter for the more fragment flag.
     * @param packet
     * @return true if MF set and false if not.
     */
    public static boolean getMoreFragmentFlag(Packet packet) {
        return packet.get(IpV4Packet.class).getHeader().getMoreFragmentFlag();
    }

    /**
     * Checks if a packet is non fragmented.
     * @param packet being checked if fragmented.
     * @return true if non fragmented and false if fragmented.
     */
    public static boolean isNonFragmented(Packet packet) {
        return ((getOffset(packet) == 0) && !getMoreFragmentFlag(packet));
    }

    /**
     * Getter for the fragments map.
     * @return the fragment map.
     */
    public static Map<Integer, List<IpV4Packet>> getFragments() {
        return fragments;
    }

    /**
     * Getter for the original packet map.
     * @return The original packets map.
     */
    public static Map<Integer, Packet> getOriginalPackets() {
        return originalPackets;
    }

    /**
     * Getter for timestampCapture map.
     * @return the timeStampArrival map.
     */
    public static Map<Integer, Timestamp> getTimestampsCapture() {
        return timeStampArrival;
    }

    /**
     * Getter for max size.
     * @return MAX_SIZE.
     */
    public static int getMaxSize() {
        return MAX_SIZE;
    }

    /**
     * Debug method used to print all offsets of a fragment list in the fragment map.
     * @param id of packet which is having its fragment offsets printed out.
     */
    public static void printPacketOffsetList(int id) {
        List<IpV4Packet> list = fragments.get(id);
        for (IpV4Packet listPacket : list) {
            System.out.println(listPacket.getHeader().getFragmentOffset());
        }
    }

    /**
     * Debug method which prints size of a list of fragments in fragment map..
     * @param list list which is having its size printed.
     */
    public static void printListSize(List<IpV4Packet> list) {
        for (int i = 0; i < list.size(); i++) {
            System.out.println("SIZE OF LIST: " + list.size() + "\n");
        }
    }
    
    /**
     * Getter for running
     */
    public static boolean isRunning() {
    	return running;
    }
    
    /**
     * Setter for running
     */
    public static void setRunning(boolean newRunning) {
    	running = newRunning;
    }

}