package com.detectionSystem.gui;

import java.io.IOException;
import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

/**
 * This class creates a new ViewSnortPacketGUI stage.
 * @author Matej Lietava
 * @version 2020-08-01
 */
public class ViewSnortPacketGUI extends Application {

    @Override
	public void start(Stage primaryStage) throws IOException {

		// Read file fxml and draw interface.
		Parent root = FXMLLoader.load(getClass().getResource("/ViewSnortPacket.fxml"));
		primaryStage.setTitle("View snort packet information.");
		primaryStage.setScene(new Scene(root));
		primaryStage.show();	
	}
        
	public static void main(String[] args) {
		launch(args);
	}
    
}