package com.detectionSystem.gui.controllers;

import java.io.File;
import java.io.IOException;

import com.detectionSystem.database.CreateDB;
import com.detectionSystem.detectionEngine.DetectionHandler;
import com.detectionSystem.gui.DeviceListGUI;
import com.detectionSystem.gui.ToolTips;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.Tooltip;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

/**
 * This class controls the SelectRuleFileGUI.
 * @author Matej Lietava
 * @version 2020-08-05
 */
public class SelectRuleFileController {

    @FXML
    private Button selectRuleFile;
    
    @FXML
    public void initialize() throws IOException {
        // set tool tip for select rule file button
        CreateDB createDB = new CreateDB();
        createDB.createDatabase();
    	Tooltip tip = new Tooltip(ToolTips.getSelectrulefiletip());
    	selectRuleFile.setTooltip(tip);
    }

    /**
     * This method executes when the Select rule file button is pressed. Opens a File Chooser, 
     * and filters all files by .rules extension. Checks if file is null, if it isn't it sets
     * the file path in the DetectionHandler class and closes the stage.
     * @param event
     * @throws IOException
     */
    @FXML
    public void selectRuleFile(ActionEvent event) throws IOException {
        //Open file chooser.
        FileChooser chooser = new FileChooser();
		FileChooser.ExtensionFilter filter = new FileChooser.ExtensionFilter("Rule files", "*.rules");
		chooser.getExtensionFilters().add(filter);
        chooser.setTitle("Open Rule File");
        File path = chooser.showOpenDialog(new Stage());

        //Check if file is null.
        if (path != null) {
            String pathString = path.getAbsolutePath();
            DetectionHandler.setPATH_TO_RULES(pathString);
            DeviceListGUI deviceList = new DeviceListGUI();
            deviceList.start(new Stage());
            Stage stage = (Stage) selectRuleFile.getScene().getWindow();
            stage.close();
        }
    }
}