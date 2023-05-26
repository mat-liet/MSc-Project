package com.fakesnort.packetsniffer.persistence.model;

import java.io.Serializable;
import java.sql.Timestamp;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;

@Entity(name="captured_packet")
public class CapturedPacket implements Serializable, Comparable<CapturedPacket> {
	
	private static final long serialVersionUID = 1L;

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
	private int id; 
    
	@Column
    private int packetId;
	
	@Column
    private Timestamp timeStamp;
	
	@Column
    private String message;
	
	@Column
    private String packet;
	
	@Column(name = "sid")
    private int SID;

    /**
     * This is one of the constructors of this class. Sets all variables.
     * @param id the id of the packet in the database
     * @param packetId the packet if of the packet
     * @param timeStamp the time when the packet was captured
     * @param message the message of the port scan
     * @param packet the actual string representation of the packet
     * @param seen whether it has been seen or not by the gui
     */
    public CapturedPacket(int id, int packetId, Timestamp timeStamp, String message, String packet, boolean seen, int SID) {
        this.id = id;
        this.packetId = packetId;
        this.timeStamp = timeStamp;
        this.message = message;
        this.packet = packet;
        this.SID = SID;
    }

    /**
     * This is one of the constructors of this class. Sets all variables apart from timeStamp.
     * @param id the id of the packet in the database
     * @param packetId the packet if of the packet
     * @param message the message of the port scan
     * @param packet the actual string representation of the packet
     * @param seen whether it has been seen or not by the gui
     */
    public CapturedPacket(int id, int packetId, int SID, String message, String packet) {
        this.id = id;
        this.packetId = packetId;
        this.SID = SID;
        this.message = message;
        this.packet = packet;
    }
    
    public CapturedPacket(int id, int packetId, String message, String packet) {
        this.id = id;
        this.packetId = packetId;
        this.message = message;
        this.packet = packet;
    }

    /**
     * Constructor to create empty PortscanPacket.
     */
    public CapturedPacket() {}

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

	@Override
    public int compareTo(CapturedPacket packet) {
        long result =  this.timeStamp.getTime() - packet.getTimeStamp().getTime();
        return (int) result;
    }
	
//	@Override
//    public String toString() {
//        String print = "=====  Packet =====" +
//                       "\n\tID: " + this.id +
//                       "\n\tPacket ID: " + this.packetId +
//                       "\n\tTime of capture: " + this.timeStamp +
//                       "\n\tMessage about attack: " + this.message +
//                       "\n\tSID: " + this.SID +
//                       "\n\tMalicious packet: \n" + this.packet;
//                       
//        return print;
//
//    }

}
