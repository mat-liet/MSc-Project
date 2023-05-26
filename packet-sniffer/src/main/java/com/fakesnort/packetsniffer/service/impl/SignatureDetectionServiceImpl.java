package com.fakesnort.packetsniffer.service.impl;

import java.util.List;
import java.util.Map;

import org.pcap4j.packet.AbstractPacket;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.util.ByteArrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.fakesnort.packetsniffer.amqp.producer.DatabaseProducer;
import com.fakesnort.packetsniffer.model.Content;
import com.fakesnort.packetsniffer.model.ContentRuleOption;
import com.fakesnort.packetsniffer.model.Rule;
import com.fakesnort.packetsniffer.model.RulesList;
import com.fakesnort.packetsniffer.model.SignatureData;
import com.fakesnort.packetsniffer.model.SubSignature;
import com.fakesnort.packetsniffer.persistence.model.CapturedPacket;
import com.fakesnort.packetsniffer.service.Capture;
import com.fakesnort.packetsniffer.service.RuleParserService;
import com.fakesnort.packetsniffer.service.SignatureDetectionService;

@Service
public class SignatureDetectionServiceImpl implements SignatureDetectionService, InitializingBean {
	
	private static final Logger LOGGER = LoggerFactory.getLogger(SignatureDetectionServiceImpl.class);
	
	@Autowired
	private RuleParserService rulesParser;
	
	@Autowired
	private DatabaseProducer databaseProducer;
	
	private final int ANY = -1;
	
	private final RulesList rulesList = new RulesList();
	
	@Override
	public void afterPropertiesSet() throws Exception {
		rulesList.setRules(rulesParser.parseFile().getRules());
		
	}
	
	/**
     * Method that loops through RulesList and checks for known signatures.
     * @param hexStr The hex string representation of the data stored in packet.
     */
	@Override
    public void handlePacket(Packet packet) {
    	String hexStr = getHexString(getBytePayload(packet));
    	LOGGER.info(hexStr);
        for (Map.Entry<Integer, Rule> entry : rulesList.getRules().entrySet()) {
            if (headerMatches(entry.getValue(), packet)) {
                if (entry.getValue().getRuleOptions().containsKey("content")) {
                    if (matchesAllSignatures(entry.getValue(), hexStr)) {
                        System.out.println("========== WARNING: POTENTIAL ATTACK OF SID: " + entry.getKey() + " ==========");
                        // System.out.println(packet);
                        CapturedPacket snortPacket = new CapturedPacket(0, Capture.getIDPacket(packet), entry.getKey(),getMessage(entry.getValue()),  
                            packet.get(AbstractPacket.class).toString());
                        databaseProducer.sendMessage(snortPacket);                    
                    }
                }
            }
        }
    }

    /**
     * Helper method which checks if packet protocol and destination port
     * match rule protocol and packet destination
     * @param rule
     */
    private boolean headerMatches(Rule rule, Packet packet) {
        if (rule.getProtocol().equals(getProtocolString(packet)) || rule.getProtocol().equals("any")) {
            if (rule.getDstAddress().contains("$HOME_NET") || rule.getDstAddress().contains("any")) {
                if (rule.getDstPort().getPorts().contains(getDstPort(packet)) || rule.getDstPort().getPorts().contains(ANY)) {
                    return true;
                }
            }
        } 
        return false;
        
    }

    /**
     * This method goes through every content in a rule and checks all signatures.
     * @param rule rule being checked for in the packet.
     * @param hexStr hex string representation of the data in packet.
     * @return true if all signatures of a rule match and false if not.
     */
    public boolean matchesAllSignatures(Rule rule, String hexStr) {
        boolean allSigsMatch = true;

        ContentRuleOption contentOption = (ContentRuleOption) rule.getRuleOptions().get("content");
        int indexForDistance = 0;
        for (Content content : contentOption.getContentList()) {
            List<SubSignature> allSubSignatures = content.getSignatures();

            String tempHexString = hexStr;
            //no case
            boolean isNocase = content.isNocase();
            //can loop through subsigs now and change to lowercase if isNocase
            String tempHexStrLower = "";
            if (isNocase) {
                String asciiString = hexToAscii(tempHexString);
                tempHexStrLower = asciiToHex(asciiString);
            }
            //offset
            int offset = content.getOffset() * 2;

            //depth
            int depth = content.getDepth() * 2;

            //distance
            int distance = content.getDistance() * 2;

            //within
            int within = content.getWithin() * 2;

            //negator i.e "!"
            boolean negator = content.isNegator();

            //if distance present, offset == 0 and vice versa
            if (distance != 0) {
                distance += indexForDistance;
            }

            offset += distance;

            //If depth and within are 0, just use data length.
            // To be improved, made more clear
            if (depth == 0 && within == 0) {
                depth = tempHexString.length();
            } else if (depth != 0 && within == 0) {
                depth += (content.getDistance() * 2) + (content.getOffset() * 2);
            } else if (within != 0 && depth == 0) {
                depth += indexForDistance;
                depth += within;
                depth += (content.getDistance() * 2) + (content.getOffset() * 2);
            }
            
            //Loop through all signatures and check if present
            indexForDistance = checkAllSubSignatures(tempHexString, tempHexStrLower, allSubSignatures, offset, depth, isNocase);
            if ((indexForDistance == -1 && !negator) || (indexForDistance != -1 && negator)) {
                allSigsMatch = false; 
                break;
            }
        }
        return allSigsMatch;
    }

    /**
     * Loops through the signature list and checks if they are all in there. Store indexes
     * of signatures as the order the signatures come in is important.
     * @param tempHexStr the hex string that contains packet data.
     * @param subSignatures the subsignatures being searched for in hex string.
     * @param offset the offset
     * @param depth the depth
     * @return index of last signature when all signatures are present AND in order. -1 if a signature is NOT present.
     */
    private int checkAllSubSignatures(String tempHexStr, String tempHexStrLower, List<SubSignature> subSignatures, int offset, int depth, boolean nocase) {
        int indexLastSig = 0; //Index of last sig detected
        for (SubSignature subSig : subSignatures) {
            String tempActualHex = tempHexStr;
            if (subSig.getType() == SignatureData.ASCII) {
                if (nocase) { //If nocase then use the lowercase hex string.
                    tempActualHex = tempHexStrLower;
                }
            }
            int currentIndex = tempActualHex.indexOf(subSig.getHexSignature(), offset);
            if (currentIndex == -1) {
                return -1;
            }
            currentIndex += subSig.getHexSignature().length();
            if (!isDepthCorrect(depth, offset, currentIndex)) {
                return -1;
            }
            while (currentIndex < indexLastSig) {
                currentIndex = tempActualHex.indexOf(subSig.getHexSignature(), currentIndex);
                if (currentIndex == -1 || !isDepthCorrect(depth, offset, currentIndex)) {
                    return -1;
                }
            }
            indexLastSig = currentIndex;
        }
        return indexLastSig; //Return index when all present
    }

    /**
     * Checks if depth is correct for current su signature.
     * @param depth the depth.
     * @param offset the offset.
     * @param currentIndex the currentIndex.
     * @return true if depth is correct and false if not.
     */
    private boolean isDepthCorrect(int depth, int offset, int currentIndex) {
        // System.out.println("Current index: " + currentIndex);
        if (currentIndex > depth) {
            return false;
        } else {
            return true;
        }
    }
    
    /**
     * Gets the message rule option content.
     * @param rule
     * @return the String representation of the msg rule option.
     */
    private String getMessage(Rule rule) {
        List<String> listMsg = rule.getRuleOptions().get("msg").getOptionContent();
        String msg = "";
        for (String str : listMsg) {
            str = str.replaceAll("\"", "");
            msg += str;
        }
        return msg;
    }

    /**
     * A helper method which converts a hex string to an ascii string.
     * @param hexStr the hex string being converted.
     * @return the ASCII string representation.
     */
    private String hexToAscii(String hexStr) {
        StringBuilder output = new StringBuilder("");
        //remove spaces
        hexStr = hexStr.replaceAll(" ", "");
        for (int i = 0; i < hexStr.length(); i+=2) {
            String str = hexStr.substring(i, i + 2);
            output.append((char) Integer.parseInt(str, 16));
        }
        return output.toString();
    }

    /**
     * A helper method which converts ascii string to a hex string.
     * @param asciiString the string being converted to a hex string.
     * @return the hex string.
     */
    private String asciiToHex(String asciiString) {
        char[] charArr = asciiString.toCharArray();
        StringBuilder builder = new StringBuilder();
        for (char c : charArr) {
            int i = (int) c;
            String hexChar = Integer.toHexString(i).toUpperCase();
            if (hexChar.length() == 1) { //check if 1 digit, if it is add padding
                hexChar = "0" + hexChar;
            }
            builder.append(hexChar);
        }
        return builder.toString();
    }

    /**
     * A helper method which gets the payload of the packet in raw data i.e bytes.
     * @param packet the packet which the raw data is being retrieved from.
     * @return a byte[] of the raw data.
     */
    private byte[] getBytePayload(Packet packet) {
        return packet.getPayload().getPayload().getRawData();
    }

    /**
     * A helper method which turns a byte[] into a hex string.
     * @param array the byte array which is being converted to a string.
     * @return a hex string representation of the byte array.
     */
    private String getHexString(byte[] array) {
        return ByteArrays.toHexString(array, "").toUpperCase();
    }

    /**
     * A helper method that will get the string packet protocol.
     * @param packet
     * @return A string representing the protocol of the given packet.
     */
    private String getProtocolString(Packet packet) {
        // System.out.println("Protocol of packet: " + this.packet.get(IpV4Packet.class).getHeader().getProtocol().toString().toLowerCase());
        String protocol = packet.get(IpPacket.class).getHeader().getProtocol().toString().toLowerCase();
        if (protocol.contains("tcp")) {
            return "tcp";
        } else if (protocol.contains("udp")) {
            return "udp";
        } else if (protocol.contains("icmp")) {
            return "icmp";
        } else {
            return "any";
        }
    }
    
    /**
     * A helper method that will get the destination port of the packet.
     * @param packet
     * @return The destination port of the packet as int.
     */
    private int getDstPort(Packet packet) {
        if (getProtocolString(packet).equals("tcp")) {
            return packet.get(TcpPacket.class).getHeader().getDstPort().valueAsInt();
        } else if (getProtocolString(packet).equals("udp")) {
            return packet.get(UdpPacket.class).getHeader().getDstPort().valueAsInt();
        } else {
            return -1;
        }
    }
}
