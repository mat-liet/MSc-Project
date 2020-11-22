package com.detectionSystem.gui.controllers;

import java.io.IOException;
import java.util.List;

import javax.swing.JOptionPane;

import com.detectionSystem.gui.CaptureGUI;
import com.detectionSystem.gui.ToolTips;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.ListView;
import javafx.scene.control.Tooltip;
import javafx.stage.Stage;

/**
 * This class controls the DeviceListGUI.
 * @author Matej Lietava
 * @version 2020-08-01
 */
public class DeviceListController {

    @FXML
    private ListView<String> deviceList;

    @FXML
    private Button confirm;

    private static PcapNetworkInterface device;

    private List<PcapNetworkInterface> allDevs = null;

    /**
     * This method is executed on start up. Shows all network devices available to capture
     * in a list view.  
     * @throws IOException
     */
    @FXML
    public void initialize() throws IOException {
        try {
            allDevs = Pcaps.findAllDevs();
        } catch (PcapNativeException e) {
            throw new IOException(e.getMessage());
        }
        
        if (allDevs == null || allDevs.isEmpty()) {
            throw new IOException("No NIF to capture.");
        }
        for (int i = 0; i < allDevs.size(); i++) {
            deviceList.getItems().add("[" + i + "] " + allDevs.get(i));
        }
        
        //set tooltip
        Tooltip confirmTip = new Tooltip(ToolTips.getConfirmdevicetip());
        confirm.setTooltip(confirmTip);
    }

    /**
     * This method executes when the confirm button is pressed. Gets index of selected device and initializes
     * the static variable of this class to the device selected.
     * @param event
     * @throws IOException
     * @throws PcapNativeException
     * @throws NotOpenException
     */
    @FXML
    public void selectDevice(ActionEvent event) throws IOException, PcapNativeException, NotOpenException {
        int deviceIndex = deviceList.getSelectionModel().getSelectedIndex();
        if (deviceIndex < 0) {
        	JOptionPane.showMessageDialog(null, "Please select a device.");
        } else {
        	device = allDevs.get(deviceIndex);
            CaptureGUI captureGUI = new CaptureGUI();
            captureGUI.start(new Stage());
            Stage stage = (Stage) confirm.getScene().getWindow();
            stage.close();
        }
    }

    /**
     * Getter for the network device selected. 
     * @return the PcapNetworkInterface 
     */
    public static PcapNetworkInterface getPcapNetworkInterface() {
		return device;
	}
    
}