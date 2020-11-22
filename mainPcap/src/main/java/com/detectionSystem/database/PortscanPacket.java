package com.detectionSystem.database;

import java.sql.Timestamp;

/**
 * This class creates an object of an entry in the portscan_packets table.
 * @author Matej Lietava
 */
public class PortscanPacket implements Comparable<PortscanPacket> {

    private int id;
    
    private int packetId;

    private Timestamp timeStamp;

    private String message;

    private String packet;

    private boolean seen;

    /**
     * This is one of the constructors of this class. Sets all variables.
     * @param id the id of the packet in the database
     * @param packetId the packet if of the packet
     * @param timeStamp the time when the packet was captured
     * @param message the message of the port scan
     * @param packet the actual string representation of the packet
     * @param seen whether it has been seen or not by the gui
     */
    public PortscanPacket(int id, int packetId, Timestamp timeStamp, String message, String packet, boolean seen) {
        this.id = id;
        this.packetId = packetId;
        this.timeStamp = timeStamp;
        this.message = message;
        this.packet = packet;
        this.seen = seen;
    }

    /**
     * This is one of the constructors of this class. Sets all variables apart from timeStamp.
     * @param id the id of the packet in the database
     * @param packetId the packet if of the packet
     * @param message the message of the port scan
     * @param packet the actual string representation of the packet
     * @param seen whether it has been seen or not by the gui
     */
    public PortscanPacket(int id, int packetId, String message, String packet, boolean seen) {
        this.id = id;
        this.packetId = packetId;
        this.message = message;
        this.packet = packet;
        this.seen = seen;
    }

    /**
     * Constructor to create empty PortscanPacket.
     */
    public PortscanPacket() {}

    /**
     * Getter for the id.
	 * @return the id
	 */
	public int getId() {
		return id;
	}

	/**
	 * Setter for the id
	 * @param id the id to set
	 */
	public void setId(int id) {
		this.id = id;
	}

	/**
	 * Getter for packet id.
	 * @return the packetId
	 */
	public int getPacketId() {
		return packetId;
	}

	/** Setter for packet id
	 * @param packetId the packetId to set
	 */
	public void setPacketId(int packetId) {
		this.packetId = packetId;
	}

	/**
	 * Getter for timestamp
	 * @return the timeStamp
	 */
	public Timestamp getTimeStamp() {
		return timeStamp;
	}

	/**
	 * Setter for timestamp.
	 * @param timeStamp the timeStamp to set
	 */
	public void setTimeStamp(Timestamp timeStamp) {
		this.timeStamp = timeStamp;
	}

	/**
	 * Getter for message.
	 * @return the message
	 */
	public String getMessage() {
		return message;
	}

	/**
	 * Setter for message
	 * @param message the message to set
	 */
	public void setMessage(String message) {
		this.message = message;
	}

	/**
	 * Getter for packet
	 * @return the packet
	 */
	public String getPacket() {
		return packet;
	}

	/**
	 * Setter for packet
	 * @param packet the packet to set
	 */
	public void setPacket(String packet) {
		this.packet = packet;
	}

	/**
	 * Getter for seen
	 * @return the seen
	 */
	public boolean isSeen() {
		return seen;
	}

	/**
	 * Setter for seen
	 * @param seen the seen to set
	 */
	public void setSeen(boolean seen) {
		this.seen = seen;
	}

	@Override
    public int compareTo(PortscanPacket portscanPacket) {
        long result =  this.timeStamp.getTime() - portscanPacket.getTimeStamp().getTime();
        return (int) result;
    }

    public String toString() {
        String print = "===== Port scan packet =====" +
                       "\n\tID: " + this.id +
                       "\n\tPacket ID: " + this.packetId +
                       "\n\tTime of capture: " + this.timeStamp +
                       "\n\tMessage about attack: " + this.message +
                       "\n\tMalicious packet: \n" + this.packet + "\n";
        return print;

    }

    
}