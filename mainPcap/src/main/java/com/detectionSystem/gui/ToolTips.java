package com.detectionSystem.gui;

/**
 * This class tores all the tool tip texts that are used in the GUI.
 * @author Matej Lietava
 * @version 2020-08-10
 */
public abstract class ToolTips {
    
    private static final String selectRuleFileTip = "Pressing this button will open the file chooser and allow" +
    												"\nyou to choose which rule file you want the program to use to" +
    												"\nfilter packets. When a valid file is selected, you will be taken" +
    												"\nto the next screen which will allow you to select the device you" +
    												"\nwant to capture the packets on. This rule file can be changed later on" +
    												"\nif needed.";

    private static final String confirmDeviceTip = "Select the device you would like to use to capture packets with and make" +
    											   "\nsure that it is highlighted in the list. Press this button when selected." +
    											   "\nAfter selecting your device, you will be taken to the main screen of the program," +
    											   "\nwhich is the capture screen. From there you will be able to start capturing packets" +
    											   "\nand also view the captured packets.";

    private static final String startTip = "Pressing this button will start the capture of network packets. It will start the DetectionHandler " +
    									   "\nwhich will search every packet for known intrusion signatures. When this capture is started, you will " +
    									   "\nnot be able to edit your rule file or its path.";

    private static final String stopTip = "Pressing this button will stop the capture of packets. You can now your rule file or its path.";

    private static final String filterTip = "This button will allow you to filter the packets that are on your view. You can filter by packet " +
    										"\nId or by the SID of the rule that triggered the packet. The value in the textfield must be a number " +
    										"\notherwise the filter will not work.";
    
    private static final String listViewTip = "This list shows the packets that have been captured as malicious packets and are marked as unseen in the " +
    										  "\ndatabase. To add a packet already seen into this list view. Open View All, find the packet, uncheck the seen box " +
    										  "\nand save changes.";

    private static final String viewAllTip = "Pressing this button will bring up another screen which will allow you to view ALL of the packets " +
    										 "\nthat have been captured. You will be able to view the snort and portscan packets. In this window, you " +
    										 "\nwill be able to change the seen value of the packet using a checkbox. IF unchecked, packet will set the " +
    										 "\nseen to false and will show up in your list view so you can view the information in more detail.";
    
    private static final String choiceBoxTip = "Select which packet table you would like to view.";
    
    private static final String saveChangesTip = "Pressing this button will save all of the changes made in the seen column.";
    
    private static final String refreshTip = "This will refresh the table that you are viewing. It will get all packets in that table.";

    private static final String viewInfoTip = "This button will bring up a window containing the key information regarding the packet you have selected." +
    										  "\nThe information includes the packet id, SID (if a snort packet), message and the packet itself. Make sure, " +
    										  "\nto select a packet before pressing this button.";

    private static final String removeTip = "This will remove the selected packet from the list view.";

    private static final String editRuleFileTip = "When pressed, the program will open up the rule file, specified by your rule file path, in an editor. " +
    											  "\nFrom here you can add more rules or edit pre-existing rules. ";

    private static final String editRulePathTip = "When pressed, a file chooser will be started and you will be asked to select the rule file that you would " +
    											  "\nlike to use instead of the current rule file. The current rule file is specified by the label above this button.";
    
    private static final String saveTip = "After this is pressed, all of the changes made in this text area will be saved to the rule file.";
    
    private static final String cancelTip = "This will cancel the editor and close the editor screen.";
    
	/**
	 * @return the selectrulefiletip
	 */
	public static String getSelectrulefiletip() {
		return selectRuleFileTip;
	}

	/**
	 * @return the confirmdevicetip
	 */
	public static String getConfirmdevicetip() {
		return confirmDeviceTip;
	}

	/**
	 * @return the starttip
	 */
	public static String getStarttip() {
		return startTip;
	}

	/**
	 * @return the stoptip
	 */
	public static String getStoptip() {
		return stopTip;
	}

	/**
	 * @return the filtertip
	 */
	public static String getFiltertip() {
		return filterTip;
	}

	/**
	 * @return the listviewtip
	 */
	public static String getListviewtip() {
		return listViewTip;
	}

	/**
	 * @return the viewalltip
	 */
	public static String getViewalltip() {
		return viewAllTip;
	}

	/**
	 * @return the choiceboxtip
	 */
	public static String getChoiceboxtip() {
		return choiceBoxTip;
	}

	/**
	 * @return the savechangestip
	 */
	public static String getSavechangestip() {
		return saveChangesTip;
	}

	/**
	 * @return the refreshtip
	 */
	public static String getRefreshtip() {
		return refreshTip;
	}

	/**
	 * @return the viewinfotip
	 */
	public static String getViewinfotip() {
		return viewInfoTip;
	}

	/**
	 * @return the removetip
	 */
	public static String getRemovetip() {
		return removeTip;
	}

	/**
	 * @return the editrulefiletip
	 */
	public static String getEditrulefiletip() {
		return editRuleFileTip;
	}

	/**
	 * @return the editrulepathtip
	 */
	public static String getEditrulepathtip() {
		return editRulePathTip;
	}

	/**
	 * @return the savetip
	 */
	public static String getSavetip() {
		return saveTip;
	}

	/**
	 * @return the canceltip
	 */
	public static String getCanceltip() {
		return cancelTip;
	}
	
	
    
    
}