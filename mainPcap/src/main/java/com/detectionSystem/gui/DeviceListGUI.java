package com.detectionSystem.gui;

import java.io.IOException;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.event.EventHandler;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;
import javafx.stage.WindowEvent;

/**
 * This class creates a new DeviceListGUI stage.
 * @author Matej Lietava
 * @version 2020-08-01
 */
public class DeviceListGUI extends Application {
	
	@Override
	public void start(Stage primaryStage) throws IOException {
		// Read file fxml and draw interface.
		Parent root = FXMLLoader.load(getClass().getResource("/DeviceList.fxml"));
		primaryStage.setTitle("Device list");
		primaryStage.setScene(new Scene(root));
		//Ends program on close of window
		primaryStage.setOnCloseRequest(new EventHandler<WindowEvent>() {
			@Override
			public void handle(WindowEvent event) {
				Platform.exit();
				System.exit(0);
			}
		});
		primaryStage.show();	
	}
        
	public static void main(String[] args) {
		launch(args);
	}
}