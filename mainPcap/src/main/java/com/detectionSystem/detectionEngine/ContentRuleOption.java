package com.detectionSystem.detectionEngine;

import java.util.List;

/**
 * This class is a subclass of RuleOption and represents all of the
 * content rule options contained in one rule. This could be one content or multiple depending 
 * on if the rule has multiple contents present in it.
 * @author Matej Lietava
 * @version 2020-07-10
 */
public class ContentRuleOption extends RuleOption {

    private List<Content> contentList;

    /**
     * The contructor for this class. 
     * @param optionName in this case, it should be content.
     * @param contentList the list of all contents.
     */
    public ContentRuleOption(String optionName, List<Content> contentList) {
        super(optionName);
        this.contentList = contentList;
    }

    /**
     * Getter for the content list.
     * @return the content list.
     */
    public List<Content> getContentList() {
        return this.contentList;
    }

    /**
     * Setter for the content list.
     * @param contentList the contentList to be set.
     */
    public void setContentList(List<Content> contentList) {
        this.contentList = contentList;
    }

    public String toString() {
        String print = "";
        for (Content content : this.contentList) {
            print += content;
        }
        return print;
    }
    
}