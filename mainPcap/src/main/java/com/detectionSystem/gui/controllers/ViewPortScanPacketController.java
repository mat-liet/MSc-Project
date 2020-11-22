package com.detectionSystem.gui.controllers;

import java.io.IOException;

import com.detectionSystem.database.PortscanPacket;
import com.detectionSystem.gui.UpdateHandler;

import javafx.fxml.FXML;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;

/**
 * This class controls the ViewPortScanPacketGUI.
 * @author Matej Lietava
 * @version 2020-08-03
 */
public class ViewPortScanPacketController {

    @FXML
    private Label ID;
    
    @FXML
    private Label packetId;

    @FXML
    private Label timeStamp;

    @FXML
    private Label message;

    @FXML
    private TextArea packetArea;

    /**
     * This method executes on the start up of this stage.
     * @throws IOException
     */
    @FXML
    public void initialize() throws IOException {
        //Gets packet from ListViewHandler list of packets. Uses CaptureController packet index.
        PortscanPacket packet = UpdateHandler.getPacket(CaptureController.getSelectedPacket());
        
        String IDStr = Integer.toString(packet.getId());
        ID.setText(IDStr);
        
        String packetIdStr = Integer.toString(packet.getPacketId());
        packetId.setText(packetIdStr);
        
        String timeStampStr = packet.getTimeStamp().toString();
        timeStamp.setText(timeStampStr);
        
        message.setText(packet.getMessage());

        packetArea.appendText(packet.getPacket());
    }
    
}