package com.detectionSystem.detectionEngine;

import java.util.HashMap;
import java.util.Map;

/**
 * The class creates an object which stores a Map containing all rules in a rule file.
 * @author Matej Lietava
 * @version 2020-08-01
 */
public class RulesList {

    private Map<Integer, Rule> rules = new HashMap<>();

    private RuleParser parser;

    /**
     * Constructor for this class.
     * @param parser The rule parser that parses the rule file.
     */
    public RulesList(RuleParser parser) {
        this.parser = parser;
        rules = parser.parseFile();
    }

    /**
     * Getter for rule parser.
     * @return the ruleParser
     */
    public RuleParser getParser() {
        return this.parser;
    }

    /**
     * Setter for ruleParser.
     * @param parser the new parser.
     */
    public void setParser(RuleParser parser) {
        this.parser = parser;
    }

    /**
     * Getter for rulesList.
     * @return the rulesList.
     */
    public Map<Integer, Rule> getRules() {
        return this.rules;
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