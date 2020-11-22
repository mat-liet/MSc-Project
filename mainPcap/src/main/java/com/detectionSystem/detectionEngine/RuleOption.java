package com.detectionSystem.detectionEngine;

import java.util.List;

/**
 * This class represents the rule options of a Snort rule. Entries in the map 
 * all represent one rule option.
 * @author Matej Lietava
 * @version 2020-08-01
 */
public class RuleOption {

    private String optionName;

    private List<String> optionContent;

    /**
     * Constructor for this class.
     * @param optionName the optionName of the rule option.
     * @param optionContent optionContent of rule option.
     */
    public RuleOption(String optionName, List<String> optionContent) {
        this.optionName = optionName;
        this.optionContent = optionContent;
    }

    /**
     * Constructor for class that doesnt set optionContent list.
     * @param optionName the name of the rule option.
     */
    public RuleOption(String optionName) {
        this.optionName = optionName;
    }

    /**
     * Getter for optionName.
     * @return the optionName.
     */
    public String getOptionName() {
        return this.optionName;
    }

    /**
     * Setter for optionName.
     * @param optionName the new optionName.
     */
    public void setOptionName(String optionName) {
        this.optionName = optionName;
    }

    /**
     * Getter for optionContent.
     * @return the optionContent.
     */
    public List<String> getOptionContent() {
        return this.optionContent;
    }

    /**
     * Setter for optionContent.
     * @param optionContent the new optionContent.
     */
    public void setOptionContent(List<String> optionContent) {
        this.optionContent = optionContent;
    }

    public String toString() {
        String print = "";
        if (this.optionContent.size() > 1) {
            for (int i = 0; i < this.optionContent.size(); i++) {
                if (i == 0) {
                    print += this.optionContent.get(i) + "\n";
                } else {
                    print += "\t " + this.optionContent.get(i) + "\n";
                }
            }
        } else {
            print += this.optionContent.get(0) + "\n";
        }
        return print;
    }
}