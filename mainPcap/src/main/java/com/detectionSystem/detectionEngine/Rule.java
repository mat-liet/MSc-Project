package com.detectionSystem.detectionEngine;

import java.util.Map;
/**
 * This class creates a Rule object with all of the options set that appear in the rule file.
 * This will be used in the comaprison of a packet and the rules.
 * @author Matej Lietava
 * @version 2020-06-20
 */
public class Rule {

    private int SID;

    private String ruleAction;

    private String protocol;

    private String srcAddress;

    private String srcPort;

    private String dstAddress;

    private DstPort dstPort;

    private Map<String, RuleOption> ruleOptions;

    /**
     * Constructor for this class.
     * @param SID the sid of this rule.
     * @param ruleAction the action of this rule.
     * @param protocol the protocol type of this rule.
     * @param srcAddress the source address.
     * @param srcPort the source port.
     * @param dstAddress the destination address.
     * @param dstPort the destination port.
     * @param ruleOptions the Map of rule options.
     */
    public Rule(int SID, String ruleAction, String protocol, String srcAddress, String srcPort, String dstAddress, DstPort dstPort, Map<String,RuleOption> ruleOptions) {
        this.SID = SID;
        this.ruleAction = ruleAction;
        this.protocol = protocol;
        this.srcAddress = srcAddress;
        this.srcPort = srcPort;
        this.dstAddress = dstAddress;
        this.dstPort = dstPort;
        this.ruleOptions = ruleOptions;
    }
    
    /**
     * Getter for SID.
	 * @return the sID
	 */
	public int getSID() {
		return SID;
	}

	/**
     * Setter for SID.
	 * @param sID the sID to set
	 */
	public void setSID(int sID) {
		SID = sID;
	}

	/**
     * Getter for ruleAction.
	 * @return the ruleAction
	 */
	public String getRuleAction() {
		return ruleAction;
	}

	/**
     * Setter for ruleAction.
	 * @param ruleAction the ruleAction to set
	 */
	public void setRuleAction(String ruleAction) {
		this.ruleAction = ruleAction;
	}

	/**
     * Getter for protocol.
	 * @return the protocol
	 */
	public String getProtocol() {
		return protocol;
	}

	/**
     * Setter for protocol.
	 * @param protocol the protocol to set
	 */
	public void setProtocol(String protocol) {
		this.protocol = protocol;
	}

	/**
     * Getter for source address.
	 * @return the srcAddress
	 */
	public String getSrcAddress() {
		return srcAddress;
	}

	/**
     * Setter for source address.
	 * @param srcAddress the srcAddress to set
	 */
	public void setSrcAddress(String srcAddress) {
		this.srcAddress = srcAddress;
	}

	/**
     * Getter for source port.
	 * @return the srcPort
	 */
	public String getSrcPort() {
		return srcPort;
	}

	/**
     * Setter for source port.
	 * @param srcPort the srcPort to set
	 */
	public void setSrcPort(String srcPort) {
		this.srcPort = srcPort;
	}

	/**
     * Getter for dst address.
	 * @return the dstAddress
	 */
	public String getDstAddress() {
		return dstAddress;
	}

	/**
     * Setter for dstAddress.
	 * @param dstAddress the dstAddress to set
	 */
	public void setDstAddress(String dstAddress) {
		this.dstAddress = dstAddress;
	}

	/**
     * Getter for dstPort.
	 * @return the dstPort
	 */
	public DstPort getDstPort() {
		return dstPort;
	}

	/**
     * Setter for dstPort.
	 * @param dstPort the dstPort to set
	 */
	public void setDstPort(DstPort dstPort) {
		this.dstPort = dstPort;
	}

	/**
     * Getter for RuleOptions.
	 * @return the ruleOptions
	 */
	public Map<String, RuleOption> getRuleOptions() {
		return ruleOptions;
	}

	/**
     * Setter for ruleOptions.
	 * @param ruleOptions the ruleOptions to set
	 */
	public void setRuleOptions(Map<String, RuleOption> ruleOptions) {
		this.ruleOptions = ruleOptions;
	}

	public String toString() {
        String ruleOptions = "";
        for (Map.Entry<String,RuleOption> entry : this.ruleOptions.entrySet()) {
            ruleOptions += entry.getKey() + ": " + entry.getValue();
        }
        String ruleString = "======HEADER RULES======" +
                            "\nSID = " + this.SID +
                            "\nAction =  " + this.ruleAction + 
                            "\nProtocol =  " + this.protocol +
                            "\nSource address =  " + this.srcAddress +
                            "\nSource port =  " + this.srcPort +
                            "\nDestination address =  " + this.dstAddress +
                            "\nDestination port = " + this.dstPort +
                            "\n======RULE OPTIONS======" +
                            "\n" + ruleOptions;

        return ruleString;
    }
}