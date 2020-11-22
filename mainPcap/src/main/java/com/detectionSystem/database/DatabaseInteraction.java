package com.detectionSystem.database;

import java.sql.DatabaseMetaData;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.detectionSystem.gui.controllers.CaptureController;

/**
 * A class which contains all methods that interact with the database that
 * stores the packets detected to be malicous.
 * 
 * @author Matej Lietava
 * @version 2020-08-02
 */
public class DatabaseInteraction {

    private static final String SNORT_TABLE = "snort_packets";

    private static final String PORTSCAN_TABLE = "portscan_packets";

    /**
     * Adds a packet to the snort_packets database table.
     * 
     * @param packetId the packet id of the packet being added
     * @param SID      the SID number of the rule that was triggered
     * @param message  the message of the sid rule
     * @param packet   the packet that triggered the snort rule
     */
    public static void insertPacketSnort(int packetId, int SID, String message, String packet) {
        PreparedStatement statement = null;
        try {
            String sql = "INSERT INTO snort_packets (packet_id, sid, msg, packet)" + " VALUES (?, ?, ?, ?);";
            statement = CaptureController.getDb().getC().prepareStatement(sql);
            statement.setInt(1, packetId);
            statement.setInt(2, SID);
            statement.setString(3, message);
            statement.setString(4, packet);
            statement.executeUpdate();
            System.out.println("Successfully added packet.");
            // Update last time captured
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Unsuccessfully added packet.");
        }
    }

    /**
     * This adds an entry to the portscan_packets table.
     * @param packetId the packet id of the packet being added
     * @param message the message of port scan
     * @param packet the packet that triggered the port scan detector
     */
    public static void insertPacketScans(int packetId, String message, String packet) {
        PreparedStatement statement = null;
        try {
            String sql = "INSERT INTO portscan_packets (packet_id, msg, packet)" +
                            " VALUES (?, ?, ?);";
            statement = CaptureController.getDb().getC().prepareStatement(sql);
            statement.setInt(1, packetId);
            statement.setString(2, message);
            statement.setString(3, packet);
            statement.executeUpdate();
            System.out.println("Successfully added packet.");
            // Update last time captured
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Unsuccessfully added packet.");
        }
    }

    /**
     * Fetches all unseen packets from the table which is specified by the argument.
     * @param table the table which the packets are getting retrieved from
     * @return list of object PortscanPacket contianing all packets from snort_packets or
     * portscan_packets
     */
    private static List<PortscanPacket> getUnseenPackets(String table) {
        PreparedStatement statement = null;
        List<PortscanPacket> list = new ArrayList<>();

        try {
            statement = CaptureController.getDb().getC()
                    .prepareStatement(String.format("select * from %s where seen = 'false';", table));
            ResultSet rs = statement.executeQuery();
            if (!rs.wasNull()) {
                while (rs.next()) {
                    if (table.equals(SNORT_TABLE)) {
                        SnortPacket snortPacket = new SnortPacket();
                        snortPacket.setId(rs.getInt("id"));
                        snortPacket.setPacketId(rs.getInt("packet_id"));
                        snortPacket.setSID(rs.getInt("sid"));
                        snortPacket.setTimeStamp(rs.getTimestamp("captured_time"));
                        snortPacket.setMessage(rs.getString("msg"));
                        snortPacket.setPacket(rs.getString("packet"));
                        snortPacket.setSeen(rs.getBoolean("seen"));
                        list.add(snortPacket);
                        System.out.println("Successfully fetched unseen packets.");
                    } else {
                        PortscanPacket portscanPacket = new PortscanPacket();
                        portscanPacket.setId(rs.getInt("id"));
                        portscanPacket.setPacketId(rs.getInt("packet_id"));
                        portscanPacket.setTimeStamp(rs.getTimestamp("captured_time"));
                        portscanPacket.setMessage(rs.getString("msg"));
                        portscanPacket.setPacket(rs.getString("packet"));
                        portscanPacket.setSeen(rs.getBoolean("seen"));
                        list.add(portscanPacket);
                        System.out.println("Successfully fetched unseen packets.");
                    }

                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Failed due to exception of class: " + e.getClass());

        }
        return list;
    }

    /**
     * Calls both list retrievals. Merges and sorts list by timestamp.
     */
    public static List<PortscanPacket> getSortedUnseenList() {
        List<PortscanPacket> portScanList = getUnseenPackets(PORTSCAN_TABLE);
        List<PortscanPacket> snortList = getUnseenPackets(SNORT_TABLE);

        portScanList.addAll(snortList);

        //A method that compares according to timestamp
        Collections.sort(portScanList);
        
        return portScanList;
    }

    /**
     * Method that changes a packet from unseen to seen. Which table is being changed depends on the
     * String table argument.
     * @param table the table which the packet is being updated in
     * @param seen the boolean value whcih seen is being set to
     * @param id  the id of the packet in the database
     */
    public static void setSeen(String table, boolean seen, int id) {
        PreparedStatement statement = null;
        try {
            statement = CaptureController.getDb().getC().prepareStatement(String.format("UPDATE %s SET seen = %b WHERE id = %d;", table, seen, id));
            statement.executeUpdate();
            System.out.println("Successfully set seen packet.");
        } catch (Exception e) {
            e.printStackTrace();
            System.out.print("Unsuccessfully set seen packet.");
        }
    }

    /**
     * A query that returns the whole table.
     * @param table the table which the entries are being retreived from
     * @return A list which contains all entries from the specified table
     */

    public static List<PortscanPacket> getAll(String table) {
        PreparedStatement statement = null;
        List<PortscanPacket> list = new ArrayList<>();
        try {
            statement = CaptureController.getDb().getC().prepareStatement(String.format("select * from %s", table));
            ResultSet rs = statement.executeQuery();
            if (!rs.wasNull()) {
                while(rs.next()) {
                    if (table.equals(SNORT_TABLE)) {
                        SnortPacket snortPacket = new SnortPacket();
                        snortPacket.setId(rs.getInt("id"));
                        snortPacket.setPacketId(rs.getInt("packet_id"));
                        snortPacket.setSID(rs.getInt("sid"));
                        snortPacket.setTimeStamp(rs.getTimestamp("captured_time"));
                        snortPacket.setMessage(rs.getString("msg"));
                        snortPacket.setPacket(rs.getString("packet"));
                        snortPacket.setSeen(rs.getBoolean("seen"));
                        list.add(snortPacket);
                        System.out.println("Successfully fetched unseen packets.");
                    } else {
                        PortscanPacket portscanPacket = new PortscanPacket();
                        portscanPacket.setId(rs.getInt("id"));
                        portscanPacket.setPacketId(rs.getInt("packet_id"));
                        portscanPacket.setTimeStamp(rs.getTimestamp("captured_time"));
                        portscanPacket.setMessage(rs.getString("msg"));
                        portscanPacket.setPacket(rs.getString("packet"));
                        portscanPacket.setSeen(rs.getBoolean("seen"));
                        list.add(portscanPacket);
                        System.out.println("Successfully fetched unseen packets.");
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Failed due to exception of class: " + e.getClass());
            
        }
        return list;
    }

    /**
     * Gets top five captured snort rules.
     * @return Map of the top five triggered snort rules.
     */
    public static Map<Integer,Integer>  getTopSidRules() {
        Map<Integer,Integer> topMap = new HashMap<>();
        PreparedStatement statement = null;
        try {
            statement = CaptureController.getDb().getC().prepareStatement("SELECT sid, COUNT(sid) AS times FROM snort_packets GROUP BY sid ORDER BY times DESC LIMIT 5;");
            ResultSet rs = statement.executeQuery();
            if (!rs.wasNull()) {
                while (rs.next()) {
                    topMap.put(rs.getInt("sid"), rs.getInt("times"));
                }
                System.out.println("Successfully retrieved top SID rules.");
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.out.print("Unsuccessfully retrieved top SID rules.");
        }

        return topMap;
    }

    /**
     * Gets the number of packets captured.
     * @return Number of packets captured
     */
    private static int getTotalPacketsCaptured(String table) {
        int result = -1;
        PreparedStatement statement = null;
        try {
            statement = CaptureController.getDb().getC()
                    .prepareStatement(String.format("SELECT COUNT(id) FROM %s;", table));
            ResultSet rs = statement.executeQuery();
            if (!rs.wasNull()) {
                while (rs.next()) {
                    result = rs.getInt("count");
                }
                System.out.println("Successfully retrieved total packets captured.");
            }

        } catch (Exception e) {
            e.printStackTrace();
            System.out.print("Unsuccessfully retrieved total packets captured.");
        }
        return result;
    }

    /**
     * Gets number of all packets in both tables
     */
    public static int getTotalPackets() {
        int portScanPackets = getTotalPacketsCaptured(PORTSCAN_TABLE);
        int snortPackets = getTotalPacketsCaptured(SNORT_TABLE);

        return portScanPackets + snortPackets;
    }

    /**
     * Method gets last time Captured
     */
    private static Timestamp getLastCaptured(String table) {
        PreparedStatement statement = null;
        Timestamp ts = null;
        try {
            statement = CaptureController.getDb().getC().prepareStatement(
                    String.format("SELECT captured_time FROM %s ORDER BY " + "captured_time DESC LIMIT 1;", table));
            ResultSet rs = statement.executeQuery();
            if (!rs.wasNull()) {
                while (rs.next()) {
                    ts = rs.getTimestamp("captured_time");
                }
                // System.out.println("Successfully retrieved last captured.");
            } 

        } catch (Exception e) {
            e.printStackTrace();
            System.out.print("Unsuccessfully retrieved last captured.");
        }
        return ts;
    }

    /**
     * Get last time capture of both tables.
     */
    public static Timestamp getSnortAndPortCaptureTime() throws Exception {
        Timestamp tsPort = getLastCaptured(PORTSCAN_TABLE);
        Timestamp tsSnort = getLastCaptured(SNORT_TABLE);
        if (tsPort != null && tsSnort != null ) {
            if (cameAfter(tsPort, tsSnort)) {
                return tsPort;
            } else {
                return tsSnort;
            }
        } else if (tsPort == null && tsSnort != null) {
            return tsSnort;
        } else if (tsSnort == null && tsPort != null) {
            return tsPort;
        } else throw new IllegalArgumentException("No packets in tables.");
    }
    
    /**
     * Compare two timestamps.
     */
    private static boolean cameAfter(Timestamp tsPort, Timestamp tsSnort) {
        Date dateOne = new Date(tsPort.getTime());
        Date dateTwo = new Date(tsSnort.getTime());
        if (dateOne.after(dateTwo)) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * Check if a database tables exist and creates if not.
     */
    public static void checkAndCreateTables() {
        try {
            DatabaseMetaData dbm = CaptureController.getDb().getC().getMetaData();
            ResultSet snortTable = dbm.getTables(null, null, "snort_packets", null);
            if (!snortTable.next()) {
                // Table does not exist
                DatabaseTables.createSnortPacketTable();
            } else {
                System.out.println("Snort packets table exists.");
            }

            ResultSet portTable = dbm.getTables(null, null, "portscan_packets", null);
            if (!portTable.next()) {
                // Table does not exist
                DatabaseTables.createPortScanPacketTable();
            } else {
                System.out.println("Portscan packets table exists.");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}   