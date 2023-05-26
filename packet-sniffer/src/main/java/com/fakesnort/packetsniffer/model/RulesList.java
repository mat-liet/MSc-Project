package com.fakesnort.packetsniffer.model;

import java.util.HashMap;
import java.util.Map;

/**
 * The class creates an object which stores a Map containing all rules in a rule file.
 * @author Matej Lietava
 * @version 2020-08-01
 */
public class RulesList {
	
    private Map<Integer, Rule> rules = new HashMap<>();

	public RulesList(Map<Integer, Rule> rules) {
    	this.rules = rules;
    }

    public RulesList() {
	}

	/**
     * Getter for rulesList.
     * @return the rulesList.
     */
    public Map<Integer, Rule> getRules() {
        return this.rules;
    }
    
    public void setRules(Map<Integer, Rule> rules) {
		this.rules = rules;
	}

    /**
     * Helper method that prints out ruleslist.
     */
    public void printRules() {
        for (Map.Entry<Integer, Rule> entry : this.rules.entrySet()) {
            System.out.println(entry.getValue());       
        }
    }
}