package com.detectionSystem.gui.controllers;

import java.io.IOException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;

import com.detectionSystem.database.DatabaseInteraction;
import com.detectionSystem.database.PortscanPacket;
import com.detectionSystem.database.SnortPacket;
import com.detectionSystem.gui.ToolTips;

import javafx.beans.property.SimpleObjectProperty;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.ChoiceBox;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.Tooltip;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.util.Callback;

/**
 * This class controls the ViewDatabaseGUI.
 * @author Matej Lietava
 * @version 2020-08-04
 */
public class ViewDatabaseController {

    @FXML
    private ChoiceBox<String> tableChoiceBox;
    
    @FXML
    private Button saveChanges;

    @FXML
    private Button refreshButton;

    @FXML
    private TableColumn<PortscanPacket, Integer> idCol, packetIdCol;

    @FXML
    private TableColumn<PortscanPacket, Timestamp> timeStampCol;

    @FXML
    private TableColumn<PortscanPacket, String> messageCol, packetCol;

    @FXML
    private TableColumn<PortscanPacket, CheckBox> seenCol;

    @FXML
    private TableView<PortscanPacket> packetTable;

    private final String PORT_SCAN_CHOICE = "Port scans";

    private final String SNORT_CHOICE = "Snort";

    private static final String SNORT_TABLE = "snort_packets";

    private static final String PORTSCAN_TABLE = "portscan_packets";

    private List<PortscanPacket> changedPacketList = new ArrayList<>();

    /**
     * This method executes on start up of stage. Sets property value factories for all table
     * columns. Sets a listener for the choicebox so events can be executed on change of choicebox
     * value. Fills table with portscan packets. 
     * @throws IOException
     */
    @FXML
    public void initialize() throws IOException {
        //initialize property values on columns
        idCol.setCellValueFactory(new PropertyValueFactory<>("id"));
        packetIdCol.setCellValueFactory(new PropertyValueFactory<>("packetId"));
        timeStampCol.setCellValueFactory(new PropertyValueFactory<>("timeStamp"));
        messageCol.setCellValueFactory(new PropertyValueFactory<>("message"));
        packetCol.setCellValueFactory(new PropertyValueFactory<>("packet"));
        // seenCol.setCellValueFactory(new PropertyValueFactory<>("seen"));

        //set cell factory for seen column so it can be editable
        seenCol.setCellValueFactory(new Callback<TableColumn.CellDataFeatures<PortscanPacket, CheckBox>, ObservableValue<CheckBox>>() {

            @Override
            public ObservableValue<CheckBox> call(
                TableColumn.CellDataFeatures<PortscanPacket, CheckBox> arg0) {
                PortscanPacket packet = arg0.getValue();

                CheckBox checkBox = new CheckBox();

                checkBox.selectedProperty().setValue(packet.isSeen());

                checkBox.selectedProperty().addListener(new ChangeListener<Boolean>() {
                    public void changed(ObservableValue<? extends Boolean> ov, Boolean old_val, Boolean new_val) {

                        packet.setSeen(new_val);
                        changedPacketList.add(packet);
                    }
                });

                return new SimpleObjectProperty<CheckBox>(checkBox);

            }

        });

        // set tables choicebox
        List<String> tableChoices = new ArrayList<>();
        tableChoices.add(PORT_SCAN_CHOICE);
        tableChoices.add(SNORT_CHOICE);
        tableChoiceBox.getItems().setAll(tableChoices);

        // create sidcol for when needed
        TableColumn<PortscanPacket, Integer> SIDCol = new TableColumn<>("SID");
        SIDCol.setCellValueFactory(new PropertyValueFactory<>("SID"));
        tableChoiceBox.getSelectionModel().selectedIndexProperty().addListener(new ChangeListener<Number>() {

            // if the item of the list is changed
            public void changed(ObservableValue ov, Number value, Number new_value) {

                if (new_value.intValue() == 1) {
                    List<PortscanPacket> allSnortPackets = DatabaseInteraction.getAll(SNORT_TABLE);
                    packetTable.getColumns().add(2, SIDCol);
                    packetTable.getItems().clear();
                    packetTable.getItems().addAll(allSnortPackets);
                } else {
                    packetTable.getItems().clear();
                    packetTable.getColumns().remove(SIDCol);
                    List<PortscanPacket> allPortscanPackets = DatabaseInteraction.getAll(PORTSCAN_TABLE);
                    packetTable.getItems().addAll(allPortscanPackets);
                }
            }
        });

        tableChoiceBox.setValue(PORT_SCAN_CHOICE);

        // Get all portscan entries
        // List<PortscanPacket> portscanTablePackets = DatabaseInteraction.getAll(PORTSCAN_TABLE);

        // packetTable.getItems().addAll(portscanTablePackets);
        
        //set tool tips
        setTooltips();
    }

    /**
     * This method executes when the refresh button is pressed. Refreshes the table views. Checks if
     * snort packet table or portscan packet table.
     * @param event
     * @throws IOException
     */
    @FXML
    public void refreshTable(ActionEvent event) throws IOException {
        if (tableChoiceBox.getValue().equals(PORT_SCAN_CHOICE)) {
            packetTable.getItems().clear();
            List<PortscanPacket> allPortscanPackets = DatabaseInteraction.getAll(PORTSCAN_TABLE);
            packetTable.getItems().addAll(allPortscanPackets);
        } else {
            packetTable.getItems().clear();
            List<PortscanPacket> allSnortPackets = DatabaseInteraction.getAll(SNORT_TABLE);
            packetTable.getItems().addAll(allSnortPackets);
        }
    }

    /**
     * This method executes when the save changes button is pressed. Gets all packets from list.
     * Sets all packets seen.
     * @param event
     * @throws IOException
     */
    @FXML
    public void saveChanges(ActionEvent event) throws IOException {
        // Go through all changed packets and set seen
        for (PortscanPacket packet : changedPacketList) {
            if (packet.getClass().equals(SnortPacket.class)) {
                DatabaseInteraction.setSeen(SNORT_TABLE, packet.isSeen(), packet.getId());
            } else {
                DatabaseInteraction.setSeen(PORTSCAN_TABLE, packet.isSeen(), packet.getId());
            }
        }
        changedPacketList.clear();
    }
    
    /**
     * Sets tool tips for this window.
     */
    private void setTooltips() {
    	Tooltip choiceTip, saveTip, refreshTip;
    	choiceTip = new Tooltip(ToolTips.getChoiceboxtip());
    	saveTip = new Tooltip(ToolTips.getSavechangestip());
    	refreshTip = new Tooltip(ToolTips.getRefreshtip());
    	tableChoiceBox.setTooltip(choiceTip);
    	saveChanges.setTooltip(saveTip);
    	refreshButton.setTooltip(refreshTip);
    }
    
}