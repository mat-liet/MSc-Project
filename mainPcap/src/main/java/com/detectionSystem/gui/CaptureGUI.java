package com.detectionSystem.gui;

import java.io.IOException;
import java.sql.SQLException;

import com.detectionSystem.gui.controllers.CaptureController;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.event.EventHandler;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;
import javafx.stage.WindowEvent;

/**
 * This class creates a new CaptureGUI stage.
 * @author Matej Lietava
 * @version 2020-08-01
 */
public class CaptureGUI extends Application {

	@Override
	public void start(Stage primaryStage) throws IOException {
		// Read file fxml and draw interface.
		Parent root = FXMLLoader.load(getClass().getResource("/CaptureGUI.fxml"));
		primaryStage.setTitle("Capture");
		primaryStage.setScene(new Scene(root));
		//Ends program on close of window
		//Also closes db connection.
		primaryStage.setOnCloseRequest(new EventHandler<WindowEvent>() {
			@Override
			public void handle(WindowEvent event) {
				try {
					CaptureController.getDb().getC().close();
				} catch (SQLException e) {
					System.out.println("Failed to close db connection.");
				}
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