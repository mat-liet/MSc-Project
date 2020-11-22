package com.detectionSystem.detectionEngine;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import com.detectionSystem.packetDecoder.Capture;

import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
/**
 * Class that handles what happens to the packets that are ready for inspection.
 * @author Matej Lietava
 * @version 2020-08-01
 */
public class DetectionHandler implements Runnable {

    private static RulesList rules;

    private static String PATH_TO_RULES;

    private static int totalInspected;

    private ExecutorService sigDetectionAndPortScan;

    /**
     * The constructor for this class.
     */
    public DetectionHandler() {
        RuleParser parser = new RuleParser(PATH_TO_RULES);
        rules = new RulesList(parser);
        sigDetectionAndPortScan = Executors.newCachedThreadPool();
        totalInspected = 0;
        System.out.println("Amount of rules in rule config: " + rules.getRules().size());
    }

    /**
     * Checks whether the payload of the packet is null. This means it will skip the
     * signature detection part of the system and just go to the port scan
     * detection.
     */
    @Override
    public void run() {
        System.out.println("Detection handler started...");
        while (Capture.isRunning() || !Capture.getInspectionQueue().isEmpty()) {
            // System.out.println("Detection handler running");
            try {
                Thread.sleep(5);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            if (!Capture.getInspectionQueue().isEmpty()) {
                inspectPacket();
            }
        }
        System.out.println("Detection handler shutting down. =================================");
    }

    /**
     * Method that checks whether inspection queue is empty and if it isn't it will
     * check for null payload. If null payload, check for port scan only and if not
     * null payload, check data of packet for known intrusion signatures.
     */
    private void inspectPacket() {
        Packet packet = Capture.getInspectionQueue().poll();
        totalInspected++;
        if (!isNullPayload(packet)) {
            sigDetectionAndPortScan.execute(new SignatureDetector(packet));
        }
        // Check every packet for port scans
        sigDetectionAndPortScan.execute(new PortScans(packet));
    }

    // Get data payload
    private boolean isNullPayload(Packet packet) {
        return (packet.get(IpV4Packet.class).getPayload().getPayload() == null);
    }

    /**
     * Getter for rules list.
     * 
     * @return the rules list.
     */
    public static RulesList getRuleList() {
        return rules;
    }

    /**
     * Getter for the rule path.
     * 
     * @return the PATH_TO_RULES
     */
    public static String getPATH_TO_RULES() {
        return PATH_TO_RULES;
    }

    /**
     * Setter for PATH_TO_RULES
     * 
     * @param NEW_PATH_TO_RULES the new path.
     */
    public static void setPATH_TO_RULES(String NEW_PATH_TO_RULES) {
        PATH_TO_RULES = NEW_PATH_TO_RULES;
    }

    /**
     * Getter for total packets inspected.
     */
    public static int getTotalInspected() {
        return totalInspected;
    }

}