package com.fakesnort.packetsniffer.model;

/**
 * Creates an instance of a Signature object. This class stores information regarding
 * a singular signature in a rule. A signature can be an individual string from one content field
 * or it can be the whole content field.
 * @author Matej Lietava
 * @version 2020-08-01
 */
public class SubSignature {
    
    private SignatureData type; //Hex or ascii

    private String asciiSignature;

    private String hexSignature;

    /**
     * A constructor for this class.
     * @param type type of data.
     * @param signature signature in hex or ascii representation.
     */
    public SubSignature(SignatureData type, String signature) {
        this.type = type;
        if (type == SignatureData.HEX) {
            this.hexSignature = signature;
        } else {
            this.asciiSignature = signature;
            this.hexSignature = asciiToHex(this.asciiSignature);
        }
    }

    /**
     * A helper method which converts an ascii string to a hex string.
     * @param asciiString the ascii string being converted to a hex string.
     * @return the hex string.
     */
    public static String asciiToHex(String asciiString) {
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
     * Getter for the type.
     * @return the type.
     */
    public SignatureData getType() {
        return this.type;
    }

    /**
     * Setter for the type.
     * @param type the new type.
     */
    public void setType(SignatureData type) {
        this.type = type;
    }

    /**
     * Getter for the ASCII signature.
     * @return the ASCII signature.
     */
    public String getAsciiSignature() {
        return this.asciiSignature;
    }

    /**
     * Setter for the ASCII signature.
     * @param asciiSignature the new ASCII signature.
     */
    public void setAsciiSignature(String asciiSignature) {
        this.asciiSignature = asciiSignature;
    }

    /**
     * Getter for the hex signature.
     * @return the hex signature.
     */
    public String getHexSignature() {
        return this.hexSignature;
    }

    /**
     * Setter for the hex signature.
     * @param hexSignature the new hex signature.
     */
    public void setHexSignature(String hexSignature) {
        this.hexSignature = hexSignature;
    }

}