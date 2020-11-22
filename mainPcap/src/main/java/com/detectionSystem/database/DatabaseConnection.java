package com.detectionSystem.database;
import java.sql.Connection;
import java.sql.DriverManager;

/**
 * This class is used to create a connection to the database and insert and edit tables.
 * @author Matej Lietava
 * @version 2020-08-02
 */
public class DatabaseConnection {
	
	private final String url;
	private final String user;
	private final String password;
	private Connection c;
	
	/**
	 * Constructor for class.
	 */
	public DatabaseConnection() {
		this.url = "jdbc:postgresql://localhost:5432/nids";
		this.user = "postgres";
		this.password = "";
	}

	/**
	 * Creates connection to given database.
	 */
	public void connect() {

	    try { 
	    	Class.forName("org.postgresql.Driver");
	
	        c = DriverManager.getConnection(this.getUrl(),
	        		this.getUser(), this.getPassword());
	
	         System.out.println("Database Connected...");
	         
	    } catch (Exception e) {
	        System.err.println( e.getClass().getName()+": "+ e.getMessage() );
	        System.exit(0);
	        }
	}
	
    /**
	 * Getter for connection.
	 * @return the c
	 */
	public Connection getC() {
		return c;
	}

	/**
	 * Getter for the url variable.
	 * @return the url
	 */
	public String getUrl() {
		return url;
	}

	/**
	 * Getter for the user variable.
	 * @return the user
	 */
	public String getUser() {
		return user;
	}

	/**
	 * Getter for the password variable.
	 * @return the password
	 */
	public String getPassword() {
		return password;
	}
	
	public static void main(String[] args) {
        DatabaseConnection connection = new DatabaseConnection();
        connection.connect();
        // DatabaseTables.dropTable("snort_packets");
        // DatabaseTables.dropTable("portscan_packets");
        // DatabaseTables.createSnortPacketTable();
        // DatabaseTables.createPortScanPacketTable();
        
	}
}