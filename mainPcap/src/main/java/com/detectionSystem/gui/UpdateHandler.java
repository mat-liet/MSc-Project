package com.detectionSystem.gui;

import java.util.ArrayList;
import java.util.List;

import com.detectionSystem.database.DatabaseInteraction;
import com.detectionSystem.database.PortscanPacket;
import com.detectionSystem.database.SnortPacket;
import com.detectionSystem.gui.controllers.CaptureController;

import javafx.application.Platform;
import javafx.scene.chart.BarChart;
import javafx.scene.control.Label;
import javafx.scene.control.ListView;

/**
 * This class is executed every second and updates the few GUI components in the CaptureGUI.
 * @author Matej Lietava
 * @version 2020-08-01
 */
public class UpdateHandler implements Runnable {
	
    private Label sizeOfQueueValue;
    
    private Label totalPacketsInspected;

    private ListView<String> unseenPacketList;

    private BarChart<String, Number> topSnortTrig;

    private Label totalPacketsCaptured;

    private Label timeOfLastAttack;

    private static List<PortscanPacket> allPackets = new ArrayList<>();
    
    private static List<PortscanPacket> unseenPacketListIndex = new ArrayList<>();

    private static boolean FILTER_CHANGED = false;

    private static String FILTER_NAME = "All";

    private static int FILTER_VALUE;

    private static final String SNORT_TABLE = "snort_packets";

    private static final String PORTSCAN_TABLE = "portscan_packets";

    /**
     * Constructor for this class. Takes the ListView, BarChart, and Label which it will be updating as
     * an argument.
     * @param unseenPacketList the ListView being updated.
     * @param topSnortTrig the graph being updated.
     * @param totalPacketsCaptured the label being updated.
     */
    public UpdateHandler(Label sizeOfQueueValue, Label totalPacketsInspected, ListView<String> unseenPacketList, BarChart<String, Number> topSnortTrig, Label timeOfLastAttack, 
                        Label totalPacketsCaptured) {
        this.sizeOfQueueValue = sizeOfQueueValue;
        this.totalPacketsInspected = totalPacketsInspected;
    	this.unseenPacketList = unseenPacketList;
        this.topSnortTrig = topSnortTrig;
        this.timeOfLastAttack = timeOfLastAttack;
        this.totalPacketsCaptured = totalPacketsCaptured;
    }

    @Override
    public void run() {
        System.out.println("UpdateHandler started...");
        //Run later so no exception thrown.
        Platform.runLater(new Runnable(){
            @Override
            public void run() {
                // Get all unseen packets.
                List<PortscanPacket> newPackets = DatabaseInteraction.getSortedUnseenList();
                if (newPackets.size() != 0) {               
                    for (PortscanPacket packet : newPackets) {
                        // Each packet add to viewed packets list
                        allPackets.add(packet);
                        if (packet.getClass().equals(SnortPacket.class)) {
                            DatabaseInteraction.setSeen(SNORT_TABLE, true, packet.getId());
                        } else {
                            DatabaseInteraction.setSeen(PORTSCAN_TABLE, true, packet.getId());
                        }

                        
                    }
                    // update stats graph
                    CaptureController.updateGraph(topSnortTrig);

                    //update total packets captured
                    CaptureController.updateTotal(totalPacketsCaptured);

                }
                CaptureController.updateTimeOflastAttack(timeOfLastAttack);
                CaptureController.setSizeOfQueue(sizeOfQueueValue);
                CaptureController.setTotalInspected(totalPacketsInspected);
                
                List<PortscanPacket> filterPackets = new ArrayList<>();

                //Check if filter changed.
                if (FILTER_CHANGED) {
                    unseenPacketList.getItems().clear();
                    unseenPacketListIndex.clear();
                    FILTER_CHANGED = false;
                    filterPackets = allPackets;
                } else {
                    filterPackets = newPackets;
                }
                
                //Depending on filter name, do following.
                if (!FILTER_NAME.equals("All")) {
                    if (FILTER_NAME.equals("Packet Id")) {
                        for (PortscanPacket packet : filterPackets) {
                            if (packet.getPacketId() == FILTER_VALUE) {
                                unseenPacketListIndex.add(packet);
                                if (packet.getClass().equals(SnortPacket.class)) {
                                    SnortPacket snortPacket = (SnortPacket) packet;
                                    // Add header to list view
                                    unseenPacketList.getItems().add(
                                            "Snort packet captured | ID: " + snortPacket.getId() + " | SID: " + snortPacket.getSID()+ " | Time: " + snortPacket.getTimeStamp());
                                } else {
                                    // Add header to list view
                                    unseenPacketList.getItems().add("Portscan packet captured | ID: " + packet.getId() + "| Time: "
                                            + packet.getTimeStamp());
                                }
                            }
                        }
                    } else if (FILTER_NAME.equals("SID")) {
                        for (PortscanPacket packet : filterPackets) {
                            if (packet.getClass().equals(SnortPacket.class)) {
                                SnortPacket snortPacket = (SnortPacket) packet;
                                if (snortPacket.getSID() == FILTER_VALUE) {
                                    unseenPacketListIndex.add(packet);
                                    //Add header to list view
                                    unseenPacketList.getItems().add(
                                "Snort packet captured | ID: " + snortPacket.getId() + " | SID: " + snortPacket.getSID()+ " | Time: " + snortPacket.getTimeStamp());
                                }
                            }
                        }
                    }
                } else {
                    for (PortscanPacket packet : filterPackets) {
                        unseenPacketListIndex.add(packet);
                        if (packet.getClass().equals(SnortPacket.class)) {
                            SnortPacket snortPacket = (SnortPacket) packet;
                            // Add header to list view
                            unseenPacketList.getItems().add(
                                    "Snort packet captured | ID: " + snortPacket.getId() + " | SID: " + snortPacket.getSID()+ " | Time: " + snortPacket.getTimeStamp());
                        } else {
                            //Add header to list view
                            unseenPacketList.getItems().add("Portscan packet captured | ID: " + packet.getId() + "| Time: "
                                    + packet.getTimeStamp());
                        }
                    }

                }
               
            }
            
        });

    }
    
    /**
     * Method that checks whether allPackets contains packet with same id
     */
    private boolean isPacketOnView(PortscanPacket packet) {
    	for (PortscanPacket packetTwo : allPackets) {
    		if (packet.getId() == packetTwo.getId()) {
    			return true;
    		}
    	}
    	return false;
    }

    /**
     * Getter for a specific packet in the onViewPacketIndex list.
     * @param index the index of the packet in the list.
     * @return the packet.
     */
    public static PortscanPacket getPacket(int index) {
        return unseenPacketListIndex.get(index);
    }

    /**
     * Getter for allOnViewPacketList
     * @return the allOnViewPacketList
     */
    public static List<PortscanPacket> getAllPacketsList() {
        return allPackets;
    }

    /**
     * Getter for onViewPacketIndexList
     * @return the onViewPacketIndexList
     */
    public static List<PortscanPacket> getUnseenPacketListIndex() {
        return unseenPacketListIndex;
    }

    /**
     * Setter for FILTER_VALUE.
     * @param filterValue the new FILTER_VALUE.
     */
    public static void setFILTER_VALUE(int filterValue) {
        FILTER_VALUE = filterValue;
    }

    /**
     * Setter for FILTER_NAME.
     * @param filterName the new FILTER_NAME.
     */
    public static void setFILTER_NAME(String filterName) {
        FILTER_NAME = filterName;
    }

    /**
     * Getter for FILTER_CHANGED.
     * @return the FILTER_CHANGED.
     */
    public static boolean getFilter_Changed() {
        return FILTER_CHANGED;
    }

    /**
     * Setter for FILTER_CHANGED.
     * @param newFilter_flag the new FILTER_CHANGED.
     */
    public static void setFilter_Changed(boolean newFilter_flag) {
        FILTER_CHANGED = newFilter_flag;
    }
    
}