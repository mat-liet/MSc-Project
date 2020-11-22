package com.detectionSystem.gui.controllers;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Iterator;

import javax.swing.JOptionPane;

import com.detectionSystem.detectionEngine.DetectionHandler;
import com.detectionSystem.gui.ToolTips;

import javafx.application.Platform;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.TextArea;
import javafx.scene.control.Tooltip;
import javafx.stage.Stage;

/**
 * This class controls the RuleFileEditorGUI.
 * @author Matej Lietava
 * @version 2020-08-05
 */
public class RuleFileEditorController {
	
	@FXML
	private Button saveButton;
	
	@FXML
	private Button cancelButton;
	
	@FXML
	private TextArea ruleFileText;

	private static String ruleFilePath;
	
	/**
	 * This method executes on start up. Gets the rule file path from DetectionHandler and
	 * checks if null. If not, print file out into the TextArea.
	 * @throws IOException
	 */
	@FXML
	public void initialize() throws IOException {
		//set tool tips
		setToolTips();
		
		ruleFilePath = DetectionHandler.getPATH_TO_RULES();
		int counter = 0;
		if (ruleFilePath != null) {
			BufferedReader reader = new BufferedReader(new FileReader(new File(ruleFilePath)));
			String line = "";
			while ((line = reader.readLine()) != null) {
				counter ++;
//				System.out.println("Line number: " + counter);
				ruleFileText.appendText(line + "\n");
			}
			reader.close();
		} else {
			//Have to run later as window might not be rendered.
			Platform.runLater(new Runnable(){
				@Override
				public void run() {
					Stage stage = (Stage) saveButton.getScene().getWindow();
            		stage.close();
				}
			});
		}
	}
	
	/**
	 * This method executes when the save button is pressed. Creates a new BufferedWriter and
	 * retrieves everything in the TextArea. Writes everything in TextArea to the file.
	 * @param event
	 * @throws IOException
	 */
	@FXML
	public void saveChanges(ActionEvent event) throws IOException {
		//Get all text from the TextArea
		ObservableList<CharSequence> fileText = ruleFileText.getParagraphs();
	    Iterator<CharSequence>  iterator = fileText.iterator();
	    try {
			//Create writer
	    	BufferedWriter writer = new BufferedWriter(new FileWriter(new File(ruleFilePath)));
			while (iterator.hasNext()) {
				//Write all lines to file
				CharSequence sequence = iterator.next();
				writer.append(sequence);
				writer.newLine();
			}
			writer.close();
			JOptionPane.showMessageDialog(null, "Saved to rule file.");
		} catch (IOException e) {
			JOptionPane.showMessageDialog(null, "Error saving to rule file.");
		}   
	}
	
	/**
	 * This method executes when the cancel button is pressed. Closes the stage.
	 * @param event
	 * @throws IOException
	 */
	@FXML
	public void cancelScreen(ActionEvent event) throws IOException {
		Stage stage = (Stage) cancelButton.getScene().getWindow();
		stage.close();
	}
	
	/**
	 * 
	 */
	private void setToolTips() {
		Tooltip saveTip, cancelTip;
		saveTip = new Tooltip(ToolTips.getSavetip());
		cancelTip = new Tooltip(ToolTips.getCanceltip());
		saveButton.setTooltip(saveTip);
		cancelButton.setTooltip(cancelTip);
	}
}
