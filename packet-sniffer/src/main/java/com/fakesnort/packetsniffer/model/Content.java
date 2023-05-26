package com.fakesnort.packetsniffer.model;

import java.util.ArrayList;
import java.util.List;

/**
 * This class is used to create a representation of the content rule option of Snort rules.
 * It contains some/most of the suboptions available for the content rule option.
 * @author Matej Lietava
 * @version 2020-07-10
 */
public class Content {

    private List<SubSignature> signatures;

    private int offset;

    private int depth;

    private int within;

    private int distance;

    private boolean nocase;

    private boolean negator;

    private final String DEPTH = "depth";

    private final String OFFSET = "offset";

    private final String DISTANCE = "distance";

    private final String WITHIN = "within";

    private final String NOCASE = "nocase";

    private static final String BYTE_SEQUENCE_INDICATOR = "|";

    /**
     * The contructor for this class. Takes a String variable as a parameter.
     * The String is then parsed and the field variables are initialized.
     * @param contentString
     */
    public Content(String contentString) {
        //Set negator
        if (contentString.trim().charAt(0) == '!') {
            this.negator = true;
        } else {
            this.negator = false;
        }
        //Set signatures
        this.signatures = getIndividualSignatures(getContentSignature(contentString));
        
        if (isKeyWordSet(contentString, OFFSET)) {
            this.offset = getKeyWordValue(contentString, OFFSET);
        }
        //Set depth
        if (isKeyWordSet(contentString, DEPTH)) {
            this.depth = getKeyWordValue(contentString, DEPTH);
        }
        //Set distance
        if (isKeyWordSet(contentString, DISTANCE)) {
            this.distance = getKeyWordValue(contentString, DISTANCE);
        }
        //Set within
        if (isKeyWordSet(contentString, WITHIN)) {
            this.within = getKeyWordValue(contentString, WITHIN);
        }
        //Set nocase
        this.nocase = isKeyWordSet(contentString, NOCASE);
        if (this.nocase) {
            //If nocase, transform the signatures into lowercase, so doesn't have to be done runtime.
            for (SubSignature subSig : this.signatures) {
                if (subSig.getType() == SignatureData.ASCII) {
                    String nocaseAscii = subSig.getAsciiSignature().toLowerCase();
                    String hexString = SubSignature.asciiToHex(nocaseAscii);
                    subSig.setHexSignature(hexString);
                }
            }
        }
    
    }

    /**
     * This method parses the content string given in the construction of this object. If multiple signatures
     * given in same content string i.e Hello|08 09 12|World, they are parsed and stored separately.
     * @param contentString the content string which is being parsed
     * @return A list of subsignatures which correspond to one content rule option.
     */
    private List<SubSignature> getIndividualSignatures(String contentString) {
        // System.out.println("Full content string: " + contentString);
        List<SubSignature> allSignatures = new ArrayList<SubSignature>();
        if (contentString.contains(BYTE_SEQUENCE_INDICATOR)) {
            boolean inByteCode = false;
            int indexBytesBegin = 0;
            int indexBytesEnd = 0;
            for (int i = 0; i < contentString.length(); i++) {
                if (isByteCodeBegin(contentString.charAt(i), inByteCode)) { // Is first pipe "|", i.e start of byte
                                                                            // sequence
                    inByteCode = true;
                    indexBytesBegin = i;
                } else if (isByteCodeEnd(contentString.charAt(i), inByteCode)) { // Or is second pipe, i.e end of byte
                                                                                 // sequence
                    inByteCode = false;
                    indexBytesEnd = i;
                    String byteSig = contentString.substring(indexBytesBegin + 1, indexBytesEnd); 
                    String byteSigNoSpace = byteSig.replaceAll(" ", "");    //Only store no space byte sequence as hex string is kept as no space                      
                                                                             //This is because it will help with index                     
                    SubSignature sig = new SubSignature(SignatureData.HEX, byteSigNoSpace);
                    // System.out.println("Sub sig: " + sig.getHexSignature());
                    allSignatures.add(sig);
                } else if (contentString.charAt(i) != '|' && !inByteCode) { // not in bytecode sequence and not a pipe.
                                                                            // i.e a normal string
                    // System.out.println("I have reached a string");
                    int endIndex = contentString.indexOf(BYTE_SEQUENCE_INDICATOR, i);
                    String normalStringSig = "";
                    // If no "|" in string
                    if (endIndex < 0) {
                        // System.out.println("I have reached the final string");
                        normalStringSig = contentString.substring(i, contentString.length());
                        // System.out.println("Final String sig: " + normalStringSig);
                        // i = contentString.length();
                        SubSignature sigString = new SubSignature(SignatureData.ASCII, normalStringSig);
                        allSignatures.add(sigString);
                        break;
                    } else {
                        normalStringSig = contentString.substring(i, endIndex);
                        i = endIndex - 1;
                        SubSignature sigString = new SubSignature(SignatureData.ASCII, normalStringSig);
                        // System.out.println("Sub sig: " + sigString.getHexSignature());
                        allSignatures.add(sigString);
                    }
                }
            }
        } else {
            SubSignature signature = new SubSignature(SignatureData.ASCII, contentString);
            // System.out.println("Sub sig: " + signature.getHexSignature());
            allSignatures.add(signature);
        }
        return allSignatures;
    }

    /**
     * A helper method which checks if a bytecode sequence is starting when signature being parsed.
     * @param c The current character being parsed.
     * @param inByteCode If inside bytecode sequence.
     * @return true if beginning of byecode sequence and false if not beginning of byetcode sequence.
     */
    private boolean isByteCodeBegin(char c, boolean inByteCode) {
        return (c == '|' && !inByteCode);
    }

    /**
     * Helper method which checks if bytecode sequencing is ending.
     * @param c the char being parsed.
     * @param inByteCode the boolean value which states if inside of bytecode sequence.
     * @return true if end of bytecode sequence or false if not the end.
     */
    private boolean isByteCodeEnd(char c, boolean inByteCode) {
        return (c == '|' && inByteCode);
    }

    /**
     * Gets the content in between the apostrophes.
     * @param contString The string being parsed.
     * @return the String between the apostrophes.
     */
    private String getContentSignature(String contString) {
        int indexFirstApostrophe = contString.indexOf("\"");
        int indexLastApostrophe = contString.lastIndexOf("\"");
        String content = contString.substring(indexFirstApostrophe + 1, indexLastApostrophe);
        return content;
    }

    /**
     * This method retrieves the value belonging to the given keyword name. 
     * @param fullContent the content string which contains the value.
     * @param keyword the keyword which the value belongs to.
     * @return the value belonging to the keyword.
     */
    private int getKeyWordValue(String fullContent, String keyword) {
        int indexOfKeyword = fullContent.indexOf(keyword) + keyword.length();
        StringBuilder keywordStr = new StringBuilder("");
        for (int i = indexOfKeyword; i < fullContent.length(); i++) {
            if (fullContent.charAt(i) == ',') {
                break;
            }
            keywordStr.append(fullContent.charAt(i));
        }
        String keywordNoSpaces = keywordStr.toString().trim();
        if (keywordNoSpaces.equals("len")) {
            return 0;
        }
        return Integer.parseInt(keywordNoSpaces);
    }

    /**
     * Checks if keyword is contained in the String content.
     * @param content the string which may/may not contain the keyword.
     * @param keyword the keyword being searched in the content string.
     * @return true if keyword present in content or false if not in content.
     */
    private boolean isKeyWordSet(String content, String keyword) {
        if (content.contains(keyword)) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * Getter signatures list.
	 * @return the signatures
	 */
	public List<SubSignature> getSignatures() {
		return signatures;
	}

	/**
     * Setter for signatures list.
	 * @param signatures the signatures to set
	 */
	public void setSignatures(List<SubSignature> signatures) {
		this.signatures = signatures;
	}

	/**
     * Getter for offset.
	 * @return the offset
	 */
	public int getOffset() {
		return offset;
	}

	/**
     * Setter for offset.
	 * @param offset the offset to set
	 */
	public void setOffset(int offset) {
		this.offset = offset;
	}

	/**
     * Getter for depth.
	 * @return the depth
	 */
	public int getDepth() {
		return depth;
	}

	/**
     * Setter for depth.
	 * @param depth the depth to set
	 */
	public void setDepth(int depth) {
		this.depth = depth;
	}

	/**
     * Getter for within.
	 * @return the within
	 */
	public int getWithin() {
		return within;
	}

	/**
     * Setter for within.
	 * @param within the within to set
	 */
	public void setWithin(int within) {
		this.within = within;
	}

	/**
     * Getter for distance.
	 * @return the distance
	 */
	public int getDistance() {
		return distance;
	}

	/**
     * Setter for distance.
	 * @param distance the distance to set
	 */
	public void setDistance(int distance) {
		this.distance = distance;
	}

	/**
     * Getter for nocase.
	 * @return the nocase
	 */
	public boolean isNocase() {
		return nocase;
	}

	/**
     * Setter for nocase.
	 * @param nocase the nocase to set
	 */
	public void setNocase(boolean nocase) {
		this.nocase = nocase;
	}

	/**
     * Getter for negator.
	 * @return the negator
	 */
	public boolean isNegator() {
		return negator;
	}

	/**
     * Setter for negator
	 * @param negator the negator to set
	 */
	public void setNegator(boolean negator) {
		this.negator = negator;
	}

    /**
     * Helper method for the toString method.
     * @return a string containing all the subsignatures of this content object.
     */
	public String getAllSignatures() {
        String str = "";
        for (SubSignature subSig : this.signatures) {
            str += "\n\t\tHex representation: " + subSig.getHexSignature() + " " +
                   "\n\t\tASCII representation: " + subSig.getAsciiSignature();
        }
        return str;
    }

    public String toString() {
        String print = "\n\tSignatures: " + getAllSignatures() +
                       "\n\tOffset: " + this.offset +
                       "\n\tDepth: " + this.depth +
                       "\n\tDistance: " + this.distance +
                       "\n\tWithin: " + this.within +
                       "\n\tNocase: " + this.nocase +
                       "\n\tNegator: " + this.negator + "\n";
        return print;
    }
}
