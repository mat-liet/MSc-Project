package com.detectionSystem.database;

import java.util.concurrent.ConcurrentLinkedQueue;

import com.detectionSystem.packetDecoder.Capture;

/**
 * This class creates a class that inserts packets from a queue to a database.
 * Contains a static ConcurrentLinkedQueue which contains the malicous packets.
 * @author Matej Lietava
 * @version 2020-08-08
 */
public class DatabaseHandler implements Runnable {

    private static ConcurrentLinkedQueue<PortscanPacket> databaseInsertionQueue = new ConcurrentLinkedQueue<>();

    public DatabaseHandler() {}
    
    @Override
    public void run() {
        System.out.println("Database handler started...");
        while (Capture.isRunning() || !databaseInsertionQueue.isEmpty()) {
            // System.out.println("DB HANDLER");
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            if (!databaseInsertionQueue.isEmpty()) {
                //Check if snort or port packet
                if (databaseInsertionQueue.peek().getClass().equals(SnortPacket.class)) {
                    //If snort
                    SnortPacket snortPacket = (SnortPacket) databaseInsertionQueue.poll(); //Remove from queue
                    DatabaseInteraction.insertPacketSnort(snortPacket.getPacketId(), snortPacket.getSID(), 
                                                            snortPacket.getMessage(), snortPacket.getPacket());
                } else {
                    //If port
                    PortscanPacket portscanPacket = databaseInsertionQueue.poll(); //Remove from queue
                    DatabaseInteraction.insertPacketScans(portscanPacket.getPacketId(), 
                                                            portscanPacket.getMessage(), portscanPacket.getPacket());
                }
            }
        }
    }

    /**
     * Getter for the database queue.
     * @return a ConcurrentLinkedQueue which contains all packets to be added to database
     */
    public static ConcurrentLinkedQueue<PortscanPacket> getDatabaseInsertionQueue() {
        return databaseInsertionQueue;
    }
    
}