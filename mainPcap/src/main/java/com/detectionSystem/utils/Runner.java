package com.detectionSystem.utils;

import java.io.IOException;
import java.util.Scanner;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import com.detectionSystem.database.DatabaseConnection;
import com.detectionSystem.detectionEngine.DetectionHandler;
import com.detectionSystem.packetDecoder.Capture;
import com.detectionSystem.packetDecoder.Defragmenter;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapHandle.PcapDirection;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.util.NifSelector;

public class Runner {

    private static DatabaseConnection db = new DatabaseConnection();

    public static DatabaseConnection getDb() {
        return db;
    }

    public static void main(String[] args) throws PcapNativeException, NotOpenException, IOException {
        PcapNetworkInterface device = new NifSelector().selectNetworkInterface();
        PcapHandle handle = device.openLive(65536, PromiscuousMode.PROMISCUOUS, 50);
        handle.setDirection(PcapDirection.IN);
        // String filter = "tcp[13] & 41 != 0";
        // String filter = "port 80";
        // handle.setFilter(filter, BpfCompileMode.OPTIMIZE);
        
        System.out.println("Will capture indefinitely, press q to stop.");
        db.connect();
        //Start the capture thread
        ExecutorService allThreads = Executors.newFixedThreadPool(3);
        Capture cap = new Capture(handle);
        allThreads.execute(cap);

        //Start the defragmenter thread
        Runnable defrag = new Defragmenter();
        ScheduledExecutorService ex = Executors.newScheduledThreadPool(2);
        ex.scheduleAtFixedRate(defrag, 0, 1000, TimeUnit.MILLISECONDS);

        //Start the detectionhandler
        DetectionHandler detectionEngine = new DetectionHandler();
        allThreads.execute(detectionEngine);
        // ex.scheduleAtFixedRate(detectionEngine, 0, 1, TimeUnit.MILLISECONDS);
        
        //Start the scan for the stop thread
        Stopper stop = new Stopper(handle);
        Scanner scan = new Scanner(System.in);
        if (scan.hasNextLine()) {
            System.out.println("MAX SIZE OF QUEUE: " + Capture.getMaxSize());
            allThreads.execute(stop);
            scan.close();
            // Turn off defragmenter
            ex.shutdown();
            allThreads.shutdown();
            // System.exit(0);
        }
    }
}