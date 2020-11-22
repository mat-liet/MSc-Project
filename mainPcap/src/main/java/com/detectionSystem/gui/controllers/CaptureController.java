package com.detectionSystem.gui.controllers;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import javax.swing.JOptionPane;

import com.detectionSystem.database.DatabaseConnection;
import com.detectionSystem.database.DatabaseHandler;
import com.detectionSystem.database.DatabaseInteraction;
import com.detectionSystem.detectionEngine.DetectionHandler;
import com.detectionSystem.gui.RuleFileEditorGUI;
import com.detectionSystem.gui.ToolTips;
import com.detectionSystem.gui.UpdateHandler;
import com.detectionSystem.gui.ViewDatabaseGUI;
import com.detectionSystem.gui.ViewPortScanPacketGUI;
import com.detectionSystem.gui.ViewSnortPacketGUI;
import com.detectionSystem.packetDecoder.Capture;
import com.detectionSystem.packetDecoder.Defragmenter;
import com.detectionSystem.utils.Stopper;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapHandle.PcapDirection;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.chart.BarChart;
import javafx.scene.chart.XYChart;
import javafx.scene.chart.XYChart.Data;
import javafx.scene.chart.XYChart.Series;
import javafx.scene.control.Button;
import javafx.scene.control.ChoiceBox;
import javafx.scene.control.Label;
import javafx.scene.control.ListView;
import javafx.scene.control.TextField;
import javafx.scene.control.Tooltip;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

/**
 * This class controls the Capture GUI.
 * 
 * @author Matej Lietava
 * @version 2020-08-05
 */
public class CaptureController {

    @FXML
    private Button startButton;

    @FXML
    private Button stopButton;

    @FXML
    private Label deviceName;

    @FXML
    private Label sizeOfQueueTitle;

    @FXML
    private Label sizeOfQueueValue;

    @FXML
    private Label totalPacketsInspected;

    @FXML
    private ChoiceBox<String> filterChoiceBox;

    @FXML
    private TextField filterValue;

    @FXML
    private Button filterButton;

    @FXML
    private ListView<String> unseenPacketList;

    @FXML
    private Button viewAll;

    @FXML
    private Button viewInformation;

    @FXML
    private Button removeButton;

    @FXML
    private Button editRuleFileButton;

    @FXML
    private Label rulePathLabel;

    @FXML
    private Button editRuleFilePath;

    @FXML
    private BarChart<String, Number> topSnortTrig;

    @FXML
    private Label timeOfLastAttack;

    @FXML
    private Label totalPacketsCaptured;

    private static DatabaseConnection db = new DatabaseConnection();

    private PcapHandle handle;

    private static int selectedPacket;

    private ExecutorService allThreads;

    private ScheduledExecutorService ex;

    private final String ALL_FILTER = "All";

    private final String PACKET_ID_FILTER = "Packet Id";

    private final String SID_FILTER = "SID";

    /**
     * This method is executed on start up. Sets the device label name, adds
     * choicebox choices, connects database, starts list and database handler.
     */
    @FXML
    public void initialize() throws IOException {

        // animated to false
        topSnortTrig.setAnimated(false);

        String name = DeviceListController.getPcapNetworkInterface().getName();
        // set label
        deviceName.setText(name);

        // set tool tips
        setToolTips();

        // set filter choicebox
        setFilterChoicebox();

        // connect to database
        db.connect();

        // check db tables exist
        DatabaseInteraction.checkAndCreateTables();

        // Start the text area handler
        ScheduledExecutorService execList = Executors.newScheduledThreadPool(3);
        UpdateHandler updateHandler = new UpdateHandler(sizeOfQueueValue, totalPacketsInspected, unseenPacketList, topSnortTrig, timeOfLastAttack, totalPacketsCaptured);
        execList.scheduleAtFixedRate(updateHandler, 0, 1000, TimeUnit.MILLISECONDS);
        // create update fx service

        // disable stop button
        stopButton.setDisable(true);

        // set rule path label
        String ruleFilePath = DetectionHandler.getPATH_TO_RULES();
        ruleFilePath = getShortenedPath(ruleFilePath);

        rulePathLabel.setText(ruleFilePath);

        // set stats graph
        updateGraph(topSnortTrig);
        
        // set last captured time 
        updateTimeOflastAttack(timeOfLastAttack);

        // update total
        updateTotal(totalPacketsCaptured);
    }

    /**
     * Shortens the file path to the last 2 directories.
     * @param ruleFilePath the rule file path to be shortened
     */
    public String getShortenedPath(String ruleFilePath) {
        String[] splitFilePath = ruleFilePath.split("/");
        String str = "";
            if (splitFilePath.length > 2) {
                int index = splitFilePath.length - 2;
                for (int i = index; i < splitFilePath.length; i++) {
                    str += "/" + splitFilePath[i];
                }
            System.out.println("Using shortened file path.");
            return str;
        } else {
            System.out.println("Using full file path.");
            return ruleFilePath;
        } 
    }

    /**
     * This method executes on the click of the start button. Once the button is clicked,
     * the executor services are created and the handle is set to capture only network traffic 
     * coming in. The detection handler and capture threads are started. The start button is disabled
     * so the system cannot be started multiple times. The stop button is enabled.
     * @param event
     * @throws IOException
     * @throws PcapNativeException
     * @throws NotOpenException
     */
    @FXML
    public void startCapture(ActionEvent event) throws IOException, PcapNativeException, NotOpenException {
    	ex = Executors.newScheduledThreadPool(3);
    	allThreads = Executors.newFixedThreadPool(6);
        handle = DeviceListController.getPcapNetworkInterface().openLive(65535, PromiscuousMode.PROMISCUOUS, 50);
       
        //set to capture network in
        handle.setDirection(PcapDirection.IN);

        //start capture thread
        Capture cap = new Capture(handle);
        allThreads.execute(cap);
        
        //turn on defragmenter
        Runnable defrag = new Defragmenter();
        ex.scheduleAtFixedRate(defrag, 0, 1000, TimeUnit.MILLISECONDS);

        //detection engine
        DetectionHandler detectionHandler = new DetectionHandler();
        allThreads.execute(detectionHandler);   
        
        //start db handler - has to be started last
        DatabaseHandler dbHandler = new DatabaseHandler();
        allThreads.execute(dbHandler);

        editRuleFileButton.setDisable(true);
        editRuleFilePath.setDisable(true);
        startButton.setDisable(true);
        stopButton.setDisable(false);
    }

    /**
     * This method executes when the stop button is pressed. The stop thread is executed and
     * the executor services are shut down. The start button is enabled and the stop button
     * is disabled.
     * @param event
     * @throws IOException
     */
    @FXML
    public void stopCapture(ActionEvent event) throws IOException {
    	// disable stop and enable start
    	stopButton.setDisable(true);
        startButton.setDisable(false);
        
        // show inspection size until shutdown
        sizeOfQueueTitle.setVisible(true);
        sizeOfQueueValue.setVisible(true);
        sizeOfQueueValue.setText(String.valueOf(Capture.getInspectionQueue().size()));
        
        Stopper stop = new Stopper(handle);
        
        ex.shutdown();
        allThreads.execute(stop);
        allThreads.shutdown();

        editRuleFileButton.setDisable(false);
        editRuleFilePath.setDisable(false);
        
    }

    /**
     * This method executes when the filter button is pressed in the 2nd tab in the
     * Capture GUI. Depending on the filter name, the ListViewHandler variables will be
     * changed accordingly. 
     * @param event
     * @throws IOException
     */
    @FXML
    public void getFilteredResults(ActionEvent event) throws IOException {
        int filterValueInt = 0;
        String filterName = filterChoiceBox.getValue(); //Get value from text field

        UpdateHandler.setFilter_Changed(true);

        if (!filterName.equals(ALL_FILTER)) {
            try {
                filterValueInt = Integer.parseInt(filterValue.getText());
            } catch (NumberFormatException e) {
                JOptionPane.showMessageDialog(null, "Has to be a number.");
            }
            UpdateHandler.setFILTER_NAME(filterName);
            UpdateHandler.setFILTER_VALUE(filterValueInt);
        } else {
            UpdateHandler.setFILTER_NAME("All");
            UpdateHandler.setFILTER_VALUE(0);
        }
    }

    /**
     * This method is executed when the view all button is pressed. 
     * Opens up the view all database gui.
     * @param event
     * @throws IOException
     */
    @FXML
    public void viewAll(ActionEvent event) throws IOException {
        ViewDatabaseGUI viewDatabase = new ViewDatabaseGUI();
        viewDatabase.start(new Stage());
    }

    /**
     * This method executes when the view information button is pressed. Gets actual value of
     * highlighted item in ListView. If it is not null, it will check if it is a snort or portscan
     * packet. If Snort, open up snort GUI or open up portscan packet GUI. Else, if not selected
     * item, give a warning message.
     * @param event
     * @throws IOException
     */
    @FXML
    public void viewInformationOfPacket(ActionEvent event) throws IOException {
        String selectedPacketHeader = unseenPacketList.getSelectionModel().getSelectedItem();
        if (selectedPacketHeader != null) {
        	if (selectedPacketHeader.contains("Snort")) {
                //If snort packet
                selectedPacket = unseenPacketList.getSelectionModel().getSelectedIndex();
                ViewSnortPacketGUI snortInfo = new ViewSnortPacketGUI();
                snortInfo.start(new Stage());
            } else {
                //If portscan packet
                selectedPacket = unseenPacketList.getSelectionModel().getSelectedIndex();
                ViewPortScanPacketGUI snortInfo = new ViewPortScanPacketGUI();
                snortInfo.start(new Stage());
            }
        } else {
        	JOptionPane.showMessageDialog(null, "Please select packet before pressing view information.");
        }
    }

    /**
     * This method executes when the remove button is pressed. Gets index and removes 
     * the packet from the ListView.
     * @param event
     * @throws IOException
     */
    @FXML
    public void removeListItem(ActionEvent event) throws IOException {
        int removeItemIndex = unseenPacketList.getSelectionModel().getSelectedIndex();
        if (removeItemIndex < 0) {
        	JOptionPane.showMessageDialog(null, "Cannot remove from already empty list.");
        } else {
        	UpdateHandler.getAllPacketsList().remove(removeItemIndex);
            unseenPacketList.getItems().remove(removeItemIndex);
            UpdateHandler.getUnseenPacketListIndex().remove(removeItemIndex);
        }
        
    }

    /**
     * This method executes when the edit rule file button is pressed int he 3rd tab.
     * Opens up the RuleFileEditorGUI.
     * @param event
     * @throws IOException
     */
    @FXML
    public void editRuleFile(ActionEvent event) throws IOException {
        RuleFileEditorGUI ruleFileEditor = new RuleFileEditorGUI();
        ruleFileEditor.start(new Stage());
        
    }

    /**
     * This method executes when the edit rule file path button is pressed.
     * Opens up a File Chooser. Checks if file selected is not null and if it isn't
     * it will set the path variable in DetectionHandler to the file selected.
     * @param event
     * @throws IOException
     */
    @FXML
    public void editRuleFilePath(ActionEvent event) throws IOException {
        FileChooser chooser = new FileChooser();
        //Create filter for just rule files.
		FileChooser.ExtensionFilter filter = new FileChooser.ExtensionFilter("Rule files", "*.rules");
		chooser.getExtensionFilters().add(filter);
        chooser.setTitle("Open Rule File");
        File path = chooser.showOpenDialog(new Stage());

        if (path != null) {
            //get string path of file selected
            String pathString = path.getAbsolutePath();
            DetectionHandler.setPATH_TO_RULES(pathString);
            System.out.println("Set new rule file.");
            pathString = getShortenedPath(pathString);
            rulePathLabel.setText(pathString);
        }
    }

    /**
     * Getter for database connection from this class.
     * @return the connection of the database
     */
    public static DatabaseConnection getDb() {
        return db;
    }

    /**
     * Getter for the selected packet index.
     * @return the selectedPacket
     */
    public static int getSelectedPacket() {
        return selectedPacket;
    }

    /**
     * Helper method. Updates graph.
     */
    public static void updateGraph(BarChart<String, Number> topSnortTrig) {
    	if (!topSnortTrig.getData().isEmpty()) {
    		topSnortTrig.getData().clear();
    		topSnortTrig.layout();
    	}
    	
        topSnortTrig.setTitle("Top 5 intrusions");
        Map<Integer, Integer> topMap = DatabaseInteraction.getTopSidRules();
        topSnortTrig.getXAxis().setLabel("SID");
        topSnortTrig.getYAxis().setLabel("Count");        
        
        Series<String, Number> series1 = new XYChart.Series<String, Number>();
        
        series1.setName("top 5");       
        for (Map.Entry<Integer,Integer> entry : topMap.entrySet()) {
            series1.getData().add(new XYChart.Data<>(String.valueOf(entry.getKey()), entry.getValue()));
        }
        
        //This is taken from 
        // https://stackoverflow.com/questions/29288669/javafx-how-to-sort-values-in-a-barchart/56592175
        Collections.sort(series1.getData(), new Comparator<XYChart.Data<String, Number>>() {

            @Override
            public int compare(Data o1, Data o2) {
                int yValue1 = (int) o1.getYValue();
                int yValue2 = (int) o2.getYValue();
                return yValue2 - yValue1;
            }
        });

        topSnortTrig.getData().addAll(series1);

        //set the tooltip for the y value, so on hover you can see the y value
        setValueTips(series1);
    }
    
    /**
     * Helper for abopve method to show count on hover.
     */
    private static void setValueTips(Series<String, Number> series1) {
    	for (Data<String, Number> entry : series1.getData()) {                
          Tooltip t = new Tooltip(entry.getYValue().toString());
          Tooltip.install(entry.getNode(), t);
      }
    }

    /**
     * Helper method to update label for total.
     */
    public static void updateTotal(Label totalPacketsCaptured) {
        //Set total number of packets captured
        int totalNumPackets = DatabaseInteraction.getTotalPackets();
        totalPacketsCaptured.setText(String.valueOf(totalNumPackets));
    }

    /**
     * Updater of the label of last time captured.
     */
    public static void updateTimeOflastAttack(Label timeOfLastAttack) {
        try {
			timeOfLastAttack.setText(DatabaseInteraction.getSnortAndPortCaptureTime().toString());
		} catch (Exception e) {
			timeOfLastAttack.setText("Null");
		}
    }
    
    /**
     * Sets tool tips for key features
     */
    private void setToolTips() {
    	// set tool tips
        Tooltip startTip, stopTip, filterTip, listViewTip, viewAllTip, viewInfoTip, removeTip, editRuleFileTip, editRulePathTip;
        startTip = new Tooltip(ToolTips.getStarttip());
        stopTip = new Tooltip(ToolTips.getStoptip());
        filterTip = new Tooltip(ToolTips.getFiltertip());
        listViewTip = new Tooltip(ToolTips.getListviewtip());
        viewAllTip = new Tooltip(ToolTips.getViewalltip());
        viewInfoTip = new Tooltip(ToolTips.getViewinfotip());	
        removeTip = new Tooltip(ToolTips.getRemovetip());
        editRuleFileTip = new Tooltip(ToolTips.getEditrulefiletip());
        editRulePathTip = new Tooltip(ToolTips.getEditrulepathtip());
        
        startButton.setTooltip(startTip);
        stopButton.setTooltip(stopTip);
        filterButton.setTooltip(filterTip);
        unseenPacketList.setTooltip(listViewTip);
        viewAll.setTooltip(viewAllTip);
        viewInformation.setTooltip(viewInfoTip);
        removeButton.setTooltip(removeTip);
        editRuleFileButton.setTooltip(editRuleFileTip);
        editRuleFilePath.setTooltip(editRulePathTip);
    }
    
    /**
     * Sets the choices in the filter choicebox.
     */
    private void setFilterChoicebox() {
    	List<String> filterChoices = new ArrayList<>();
        filterChoices.add(ALL_FILTER);
        filterChoices.add(PACKET_ID_FILTER);
        filterChoices.add(SID_FILTER);
        filterChoiceBox.getItems().setAll(filterChoices);
        filterChoiceBox.setValue(ALL_FILTER);
    }
    
    /**
     * Sets the label for packet size.
     */
    public static void setSizeOfQueue(Label sizeOfQueueValue) {
    	sizeOfQueueValue.setText(String.valueOf(Capture.getInspectionQueue().size()));
    }

    /**
     * Sets the label for total packets inspected.
     */
    public static void setTotalInspected(Label totalPacketsInspected) {
    	totalPacketsInspected.setText(String.valueOf(DetectionHandler.getTotalInspected()));
    }
}