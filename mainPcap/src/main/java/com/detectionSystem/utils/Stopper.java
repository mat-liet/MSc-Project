package com.detectionSystem.utils;

import com.detectionSystem.database.DatabaseHandler;
import com.detectionSystem.detectionEngine.DetectionHandler;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;

/**
 * This method is used to break the pcapHandle used to capture packets.
 * @author Matej Lietava
 * @version 2020-08-01
 */
public class Stopper implements Runnable {

    private PcapHandle pcapHandle;

    /**
     * Constructor for this class.
     * @param handle
     */
    public Stopper(PcapHandle handle) {
        this.pcapHandle = handle;
    }

    public void run() {
        try {
            stop();
        } catch (NotOpenException | PcapNativeException e) {
            e.printStackTrace();
        }
    }

    synchronized public void stop() throws NotOpenException, PcapNativeException {
        System.out.println("call stop");
        this.pcapHandle.breakLoop();
    }
}