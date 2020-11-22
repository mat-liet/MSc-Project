package com.detectionSystem.database;

import java.sql.PreparedStatement;
import java.sql.Statement;

import com.detectionSystem.gui.controllers.CaptureController;

/**
 * This class creates the needed tables for the system to store the detected packets.
 * @author Matej Lietava
 * @version 2020-08-04
 */
public class DatabaseTables {

	/**
	 * Creates the snort_packets table.
	 */
    public static void createSnortPacketTable() {
		try {
			//Connect to database
            Statement stmn = null;
            // DatabaseConnection db = new DatabaseConnection();
            // db.connect();
			
			//Create statement
			stmn = CaptureController.getDb().getC().createStatement();
			String sql = "CREATE TABLE snort_packets " +
            "(ID SERIAL PRIMARY KEY     NOT NULL, " +
            "PACKET_ID INT NOT NULL, " +
            "SID INT NOT NULL," +
            "CAPTURED_TIME  TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP, " +
            "MSG TEXT NOT NULL, " +
            "PACKET TEXT NOT NULL, " +
            "SEEN BOOLEAN NOT NULL DEFAULT FALSE);";
			
			stmn.executeUpdate(sql);
			stmn.close();
			// db.getC().close();
			
		} catch (Exception e) {
			System.err.println(e.getClass().getName() + ": " + e.getMessage());
			System.exit(0);
		}
		
		System.out.println("Successful creation of snort table.");
		
    }

	/**
	 * Creates the portscan_packets.
	 */
    public static void createPortScanPacketTable() {
		try {
			//Connect to database
            Statement stmn = null;
            // DatabaseConnection db = new DatabaseConnection();
            // db.connect();
			
			//Create statement
			stmn = CaptureController.getDb().getC().createStatement();
			String sql = "CREATE TABLE portscan_packets " +
            "(ID SERIAL PRIMARY KEY     NOT NULL, " +
            "PACKET_ID INT NOT NULL, " +
            "CAPTURED_TIME  TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP, " +
            "MSG TEXT NOT NULL, " +
            "PACKET TEXT NOT NULL, " +
            "SEEN BOOLEAN NOT NULL DEFAULT FALSE);";
			
			stmn.executeUpdate(sql);
			stmn.close();
			// db.getC().close();
			
		} catch (Exception e) {
			System.err.println(e.getClass().getName() + ": " + e.getMessage());
			System.exit(0);
		}
		
		System.out.println("Successful creation of  port scan table table.");
		
    }

	/**
	 * This method drops the table specified by the argument.
	 * @param table the table that is being dropped
	 */
    public static void dropTable(String table) {
        PreparedStatement stmn = null;
        DatabaseConnection db = new DatabaseConnection();
            db.connect();
		try {
			stmn = db.getC().prepareStatement(String.format("DROP TABLE IF EXISTS %s", table));
			stmn.executeUpdate();
			System.out.println("Successfully dropped table.");
			db.getC().close();
		} catch (Exception e) {
			e.printStackTrace();
		}
		
	}
    

    
}