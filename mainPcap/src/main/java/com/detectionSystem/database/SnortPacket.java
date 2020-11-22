package com.detectionSystem.database;

import java.sql.Timestamp;

/**
 * This class creates an object of an entry in the snort_packets table.
 * @author Matej Lietava
 * @version 2020-08-05
 */
public class SnortPacket extends PortscanPacket {

    private int SID;

    /**
     * This is one of the constructors of this class. Sets all variables.
     * @param id the id of the packet in the database
     * @param packetId the packet if of the packet
     * @param sid the sid of the rule that was triggered
     * @param timeStamp the time when the packet was captured
     * @param message the message of the port scan
     * @param packet the actual string representation of the packet
     * @param seen whether it has been seen or not by the gui
     */
    public SnortPacket(int id, int packetId, int SID, Timestamp timeStamp, String message, String packet, boolean seen) {
        super(id, packetId, timeStamp, message, packet, seen);
        this.SID = SID;
    }

    /**
     * This is one of the constructors of this class. Sets all variables apart from timeStamp.
     * @param id the id of the packet in the database
     * @param packetId the packet if of the packet
     * @param sid the sid of the rule that was triggered
     * @param message the message of the port scan
     * @param packet the actual string representation of the packet
     * @param seen whether it has been seen or not by the gui
     */
    public SnortPacket(int id, int packetId, int SID, String message, String packet, boolean seen) {
        super(id, packetId, message, packet, seen);
        this.SID = SID;
    }
    
    /**
     * Empty contructor for this class.
     */
    public SnortPacket() {}

    /**
     * Getter for ths id.
	 * @return the sID
	 */
	public int getSID() {
		return SID;
	}

	/**
	 * Setter for the sid.
	 * @param sID the sID to set
	 */
	public void setSID(int sID) {
		SID = sID;
	}

	public String toString() {
        String superToString = super.toString();
        superToString = superToString.replace("Port scan", "Snort");
        return superToString + "\n\tSID triggered: " + this.SID + "\n";
    }
}