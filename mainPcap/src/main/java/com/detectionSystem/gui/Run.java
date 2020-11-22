package com.detectionSystem.gui;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;

/**
 * This class is used to Run the program.
 * @author Matej Lietava
 * @version 2020-08-01
 */
public class Run {
    public static void main(String[] args) throws PcapNativeException, NotOpenException {
        SelectRuleFileGUI.main(args);
    }
}