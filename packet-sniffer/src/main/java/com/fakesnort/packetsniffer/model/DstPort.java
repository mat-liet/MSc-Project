package com.fakesnort.packetsniffer.model;

import java.util.ArrayList;
import java.util.List;

/**
 * This class holds the port numbers in an int array. Easier to then check when
 * signature detecting if port num of packet is in valid range.
 * 
 * @author Matej Lietava
 * @version 2020-08-11
 */
public class DstPort {
    
    private String name;

    private List<Integer> ports;

    private boolean negator;

    private final String HTTP_PORTS = "$HTTP_PORTS";

    private final String ORACLE_PORTS = "$ORACLE_PORTS";

    private final String SSH_PORTS = "$SSH_PORTS";

    private final String SIP_PORTS = "$SIP_PORTS";

    private final String FTP_PORTS = "$FTP_PORTS";

    private final String FILE_DATA_PORTS = "$FILE_DATA_PORTS";

    private final String RANGE = "range";

    private final String SINGLE = "single";

    private final String ANY = "any";

    /**
     * Constructor for this class.
     * @param dstPortString
     */
    public DstPort(String dstPortString) {
        dstPortString = dstPortString.trim();
        this.name = getName(dstPortString);
        this.negator = dstPortString.contains("!");
        this.ports = getPortValues(dstPortString);
    }

    /**
     * This method returns the name associated to the type of port it is.
     * @param dstPortString
     * @return
     */
    private String getName(String dstPortString) {
        if (dstPortString.contains(HTTP_PORTS)) {
            return HTTP_PORTS;
        }  else if (dstPortString.contains(ORACLE_PORTS)) {
            return ORACLE_PORTS;
        } else if (dstPortString.contains(SSH_PORTS)) {
            return SSH_PORTS;
        } else if (dstPortString.contains(SIP_PORTS)) { 
            return SIP_PORTS;
        } else if (dstPortString.contains(FTP_PORTS)) { 
            return FTP_PORTS;
        } else if (dstPortString.contains(FILE_DATA_PORTS)) { 
            return FILE_DATA_PORTS;
        } else if (dstPortString.contains(":") || dstPortString.contains("[")) {
            return RANGE;
        }else if (dstPortString.contains(ANY)) {
            return ANY;
        }  else {
            return SINGLE;
        }
    }

    /**
     * Retrieves the actual array of ports that are valid to this rule.
     * @param dstPortString
     * @return
     */
    private List<Integer> getPortValues(String dstPortString) {
        List<Integer> portList = new ArrayList<Integer>();
        if (this.name.equals(HTTP_PORTS)) {
            portList = addPortValArrayToList(Ports.getHTTP_PORTS(), portList);
        } else if (this.name.equals(ORACLE_PORTS)) {
            portList = addPortValArrayToList(Ports.getORACLE_PORTS(), portList);
        } else if (this.name.equals(FILE_DATA_PORTS)) {
            portList = addPortValArrayToList(Ports.getFILE_DATA_PORTS(), portList);
        } else if (this.name.equals(SSH_PORTS)) {
            portList = addPortValArrayToList(Ports.getSSH_PORTS(), portList);
        } else if (this.name.equals(SIP_PORTS)) {  
            portList = addPortValArrayToList(Ports.getSIP_PORTS(), portList);
        } else if (this.name.equals(FTP_PORTS)) { 
            portList = addPortValArrayToList(Ports.getFTP_PORTS(), portList);
        } else if (this.name.equals(RANGE)) {
            List<Integer> rangePortList = getPortValList(dstPortString);
            portList.addAll(rangePortList);
        } else if (this.name.equals(SINGLE)) {
            portList.add(Integer.parseInt(dstPortString.trim()));
        } else {
            portList.add(-1);
        }
        return portList;
    }

    /**
     * Helper method for above to add an int[] to a list.
     * @param portValArray
     * @return
     */
    private List<Integer> addPortValArrayToList(int[] arr, List<Integer> portList) {
        for (int i : arr) {
            portList.add(i);
        }
        return portList;
    }

    /**
     * This method will give the necessary range of ports.
     * @param portString
     * @return array of ints containing the specified range of port values
     */
    private List<Integer> getPortValList(String portString) {
        List<Integer> portList = new ArrayList<>();
        if (portString.contains("[")) {
            portString = portString.replace("[", "").replace("]", "");
            String[] splitValArr = portString.split(",");
            
            for (int i = 0; i < splitValArr.length; i++) {
                if (!splitValArr[i].contains(":")) {
                    int portAsInt = Integer.parseInt(splitValArr[i]);
                    portList.add(portAsInt);
                } else {
                    List<Integer> portListRange = getPortRange(splitValArr[i]);
                    portList.addAll(portListRange);
                }
            }
        } else if (portString.contains(":")) {
            List<Integer> portListRange = getPortRange(portString);
            portList.addAll(portListRange);
        }
        return portList;
    }

    /**
     * This helper method gets a list of ports dependent whether it is :x or x:.
     * @param portRange
     * @return list of values within a specified range
     */
    private List<Integer> getPortRange(String portRange) {
        List<Integer> portList = new ArrayList<>();
        int indexOfSignifier = portRange.indexOf(":");

        if (indexOfSignifier == 0) {
            portRange = portRange.substring(1, portRange.length());
            int startPort = Integer.parseInt(portRange);
            for (int i = 0; i < startPort; i++) {
                portList.add(i);
            }
        } else if (indexOfSignifier == portRange.length() - 1) {
            portRange = portRange.substring(0, indexOfSignifier);
            int startPort = Integer.parseInt(portRange);
            for (int i = startPort; i < 65536; i++) {
                portList.add(i);
            }
        } else {
            String[] portRangeArray = portRange.split(":");
            int startPort = Integer.parseInt(portRangeArray[0]);
            int endPort = Integer.parseInt(portRangeArray[1]);
            for (int i = startPort; i < endPort; i++) {
                portList.add(i);
            }
        }

        return portList;
    }

    /**
     * Getter for port list.
     * @return ports
     */
    public List<Integer> getPorts() {
        return this.ports;
    }

    /**
     * Setter for ports.
     * @param ports the new ports list
     */
    public void setPorts(List<Integer> ports) {
        this.ports = ports;
    }

    /**
     * Getter for negator.
     * @return negator
     */
    public boolean isNegator() {
        return this.negator;
    }

    /**
     * Setter for negator.
     * @param negator the new negator
     */
    public void setNegator(boolean negator) {
        this.negator = negator;
    }

    public String toString() {
        return this.name ;
    }
}