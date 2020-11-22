package com.detectionSystem.packetDecoder;

import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.SimpleBuilder;
import org.pcap4j.util.IpV4Helper;

/**
 * This class is executed every second. It checks whether fragmented packets are ready to be
 * rebuilt.
 * @author Matej Lietava
 * @version 2020-08-01
 */
public class Defragmenter implements Runnable {

    private static final int LIMIT = 15535;

    private static final long EXPIRY_TIME = 10000;

    private static Comparator<IpV4Packet> comparator = new ComparatorImpl();

    public Defragmenter() {}

    /**
     * This method checks if all fragments have arrived for each packet in the map. If they have,
     * it will rebuild the packet and put it into the inspection queue. If they have not all arrived,
     * it will check if the packet hasd expired. If it has expired, it will remove all fragments and time stamp.
     */
    @Override
    public void run() {
        System.out.println("Defragmenter checking...");
        for (Map.Entry<Integer, List<IpV4Packet>> entry : Capture.getFragments().entrySet()) {
            if (allFragmentsArrived(entry.getValue())) {
                System.out.println("Defragmentation on [" + entry.getKey() + "]");
                Packet builtPacket = reassemble(entry.getValue(), entry.getKey());
                if (getTotalLength(builtPacket) > LIMIT) {
                    System.out.println("PACKET TOO BIG");
                } else {
                    // System.out.println(Capture.getTimestampsCapture().get(entry.getKey()));
                    // System.out.println(builtPacket);
                    Capture.getInspectionQueue().add(builtPacket);
                }
                Capture.getFragments().remove(entry.getKey());
                Capture.getOriginalPackets().remove(entry.getKey());
                Capture.getTimestampsCapture().remove(entry.getKey());
            } else {
                if (isExpired(entry.getKey())) {
                    Capture.getFragments().remove(entry.getKey());
                    Capture.getOriginalPackets().remove(entry.getKey());
                    Capture.getTimestampsCapture().remove(entry.getKey());
                }
            }
        }

    }

    /**
     * A method that reassembles the packet using a list of fragments (other packets).
     * @param list the list of fragments.
     * @param id the id of the packet.
     * @return a rebuilt packet.
     */
    private Packet reassemble(List<IpV4Packet> list, int id) {
        final IpV4Packet defragmentedIpV4Packet = IpV4Helper
            .defragment(list);
        Packet.Builder builder = Capture.getOriginalPackets().get(id).getBuilder();
        builder.getOuterOf(IpV4Packet.Builder.class).payloadBuilder(new SimpleBuilder(defragmentedIpV4Packet));
        Packet builtPacket = builder.build();
        return builtPacket;
    }

    /**
     * A method that checks whether the list contains all of the packet it needs
     * and check offsets, offset(i) + size(i) - 20 = offset(i+1) -20 because of IPV4 header.
     * @param list The list of fragments being checked.
     */
    private boolean allFragmentsArrived(List<IpV4Packet> list) {
        if (list.size() == 1) {
            return false;
        } else {
            Collections.sort(list, comparator);
            //Check if last fragment has arrived or first fragment
            if (getMoreFragmentFlag(list.get(list.size()-1)) || getOffset(list.get(0)) != 0) {
                return false;
            } else {
                for (int i = 0; i < list.size()-1; i++) {
                    int sizeOfCurrentFragment = (getOffset(list.get(i)) * 8) + (getTotalLength(list.get(i)) - 20);
                    if (sizeOfCurrentFragment != (getOffset(list.get(i+1)) * 8)) {
                        return false;
                    }
                }
                return true;
            } 
        }
     }

     /**
      * Check the time expiring. If difference is more than 10 seconds.
      @param id the id of the packet being checked for expiry.
      */
    private boolean isExpired(int id) {
        long timeNow = System.currentTimeMillis();
        long timeCapture = Capture.getTimestampsCapture().get(id).getTime();
        if (timeNow >= (timeCapture + EXPIRY_TIME)) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * This method returns the fragment offset of the packet.
     * @param packet the packet that the offset belongs to.
     * @return the fragment offset of the packet.
     */
    private static int getOffset(Packet packet) {
        return packet.get(IpV4Packet.class).getHeader().getFragmentOffset();
    }

    /**
     * This method returns the total length of the packet as an int.
     * @param packet that the total length belongs to.
     * @return the total length of the packet.
     */
    private static int getTotalLength(Packet packet) {
        return packet.get(IpV4Packet.class).getHeader().getTotalLengthAsInt();
    }

    /**
     * Gets the more fragment flag of a packet.
     * @param packet the packet which the more fragment flag belongs to.
     * @return true if more fragment flag is set, false if not.
     */
    private static boolean getMoreFragmentFlag(Packet packet) {
        return packet.get(IpV4Packet.class).getHeader().getMoreFragmentFlag();
    }

    /**
     * Creates the comparator for the fragments.
     */
    private static final class ComparatorImpl implements Comparator<IpV4Packet> {
        @Override
        public int compare(IpV4Packet p1, IpV4Packet p2) {
          return p1.getHeader().getFragmentOffset() - p2.getHeader().getFragmentOffset();
        }
      }
}