package com.fakesnort.packetsniffer.service.impl;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.fakesnort.packetsniffer.model.Content;
import com.fakesnort.packetsniffer.model.ContentRuleOption;
import com.fakesnort.packetsniffer.model.DstPort;
import com.fakesnort.packetsniffer.model.Rule;
import com.fakesnort.packetsniffer.model.RuleOption;
import com.fakesnort.packetsniffer.model.RulesList;
import com.fakesnort.packetsniffer.service.RuleParserService;

/**
 * This class createa a rule parser that parses the rules file and creates a collection of rules.
 * @author Matej Lietava
 * @version 2020-08-01
 */
@Service
public class RuleParserServiceImpl implements RuleParserService {
	
	@Value("${ruleslist.location}")
	private String rulesFileLocation;
	
    private final int RULE_ACTION = 0;

    private final int PROTOCOL = 1;

    private final int SRCADDRESS = 2;

    private final int SRCPORT = 3;

    private final int DSTADDRESS = 5;
    
    private final int DSTPORT = 6;

    /**
     * The method which goes through every line of the rule file and gets the relevant information
     * from each rule. Creates a Map of each rule in rule file.
     * @return a Map containing each rule in the rule file.
     */
    @Override
    public RulesList parseFile() {
    	ClassLoader classLoader = getClass().getClassLoader();
        Map<Integer, Rule> listOfRules = new HashMap<>();
        try {
            BufferedReader reader = new BufferedReader(new FileReader(classLoader.getResource(rulesFileLocation).getFile()));
            String str;
            while((str = reader.readLine()) != null) {
                str = str.trim();
                if (str.length() != 0) {
                    if (str.charAt(0) == '#') {
                        str = str.substring(1, str.length()).trim();
                    }  
                    //First brake off between options and other using first bracket
                    int indexBracket = str.indexOf("(");
                    String header = str.substring(0, indexBracket);
                    String optionsString = str.substring(indexBracket, str.length());
                    //Now split header by spaces
                    String[] strArray = header.split(" +");  
                    String ruleAction = strArray[RULE_ACTION].trim();
                    String protocol = strArray[PROTOCOL].trim();
                    String srcAddress = strArray[SRCADDRESS].trim();
                    String srcPort = strArray[SRCPORT].trim();
                    String dstAddress = strArray[DSTADDRESS].trim();
                    DstPort dstPort = new DstPort(strArray[DSTPORT].trim());
                    Map<String, RuleOption> ruleOptions = getAllOptionsV2(optionsString);
                    String sidStr = ruleOptions.get("sid").getOptionContent().get(0);
                    int SID = Integer.parseInt(sidStr);
                    Rule rule = new Rule(SID, ruleAction, protocol, srcAddress, srcPort, dstAddress, dstPort, ruleOptions);
                    listOfRules.put(SID, rule);
                } else {
                    System.out.println("Should not have empty lines in rule file.");
                }
            }
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return new RulesList(listOfRules);   
    }

    /**
     * A method that parses the rule options section of a Snort rule.
     * Creates a Map containing each rule option present in the rule option section.
     * @param str the rule option in one string.
     * @return A Map containing every rule option present in rule option string.
     */
    private Map<String, RuleOption> getAllOptionsV2(String str) {
        Map<String, RuleOption> options = new HashMap<>();
        int endOfLastOption = 0;
        final String END_OPTION_INDICATOR = ";"; //indicates end of rule option
        final String OPTION_CONTENT_START = ":"; //indicates that option has content and where it starts
        boolean notFinished = true;
        while(notFinished) {
            int endOfNewOption = str.indexOf(END_OPTION_INDICATOR, endOfLastOption + 1);
            if (endOfNewOption > 0) {
                while (str.charAt(endOfNewOption - 1) == '\\') {
                    endOfNewOption = str.indexOf(END_OPTION_INDICATOR, endOfNewOption + 1);
                }
                String optionString = str.substring(endOfLastOption + 1, endOfNewOption).trim();
                endOfLastOption = endOfNewOption;
                //For most options that have name and option content
                if (optionString.contains(OPTION_CONTENT_START)) {
                    int optionNameEndIndex = optionString.indexOf(OPTION_CONTENT_START);
                    String optionName = optionString.substring(0, optionNameEndIndex);
                    String optionContent = optionString.substring(optionNameEndIndex + 1, optionString.length());
                    if (options.containsKey(optionName)) {
                        if (optionName.equals("content")) {
                            Content content = new Content(optionContent);
                            ContentRuleOption contOption = (ContentRuleOption) options.get(optionName);
                            contOption.getContentList().add(content);
                            options.put(optionName, contOption);
                        } else {
                            options.get(optionName).getOptionContent().add(optionContent);
                        }
                    } else {
                        if (optionName.equals("content")) {
                            Content content = new Content(optionContent);
                            List<Content> contentList = new ArrayList<>();
                            contentList.add(content);
                            ContentRuleOption contOption = new ContentRuleOption(optionName, contentList);
                            options.put(optionName, contOption);
                        } else {
                            List<String> optionContents = new ArrayList<>();
                            optionContents.add(optionContent);
                            RuleOption option = new RuleOption(optionName, optionContents);
                            options.put(optionName, option);
                        }
                    }
                    //If it is an option with no content
                } else {
                    if (options.containsKey(optionString)) {
                        options.get(optionString).getOptionContent().add(optionString);
                    } else {
                        List<String> optionContents = new ArrayList<>();
                        optionContents.add(optionString);
                        RuleOption option = new RuleOption(optionString, optionContents);
                        options.put(optionString, option);
                    }
                }
            } else {
                notFinished = false;
            } 
        }
        return options;
    }
}