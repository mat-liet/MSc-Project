package com.detectionSystem.gui;

import java.io.IOException;
import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

/**
 * This class creates a new ViewPortScanPacketGUI stage.
 * @author Matej Lietava
 * @version 2020-08-01
 */
public class ViewPortScanPacketGUI extends Application {
	
	@Override
	public void start(Stage primaryStage) throws IOException {

		// Read file fxml and draw interface.
		Parent root = FXMLLoader.load(getClass().getResource("/ViewPortScanPacket.fxml"));
		primaryStage.setTitle("Port scan packet information.");
		primaryStage.setScene(new Scene(root));
		primaryStage.show();	
	}
        
	public static void main(String[] args) {
		launch(args);
	}
}