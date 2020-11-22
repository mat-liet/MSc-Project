package com.detectionSystem.database;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

public class CreateDB {
    private final String url;
	private final String user;
    private final String password;
    private Connection c;
    
    public CreateDB() {
		this.url = "jdbc:postgresql://localhost:5432/";
		this.user = "postgres";
		this.password = "";
	}

	/**
	 * Creates connection to given database.
	 */
	public void createDatabase() {

	    try { 
	    	Class.forName("org.postgresql.Driver");
	
	        c = DriverManager.getConnection(this.getUrl(),
	        		this.getUser(), this.getPassword());
	
             System.out.println("Database Connected...");
             
            Statement statement = c.createStatement();
            String sql = "CREATE DATABASE nids";
            //To delete database: sql = "DROP DATABASE DBNAME";
            statement.executeUpdate(sql);
            System.out.println("Database created!");
	        c.close();
	    } catch (SQLException e) {
            System.out.println("Already exists.");
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
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
        CreateDB test = new CreateDB();
        test.createDatabase();
    }
}
