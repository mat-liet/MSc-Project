package com.fakesnort.packetsniffer.model;

/**
 * This class stores as int arrays, port ranges for special port variable names.
 * @author Matej Lietava
 * @version 2020-08-06
 */
public abstract class Ports {
    
    //Port values for Oracle ports was specified on the The Official Blog of the World Leading Open-Source IDS/IPS Snort.
    //https://blog.snort.org/2011/01/new-rule-pack-and-check-your-snortconf_04.html
    private static int[] HTTP_PORTS = {36,80,81,82,83,84,85,86,87,88,89,90,311,383,555,591,
        593,631,801,808,818,901,972,1158,1220,1414,1533,1741,
        1830,1942,2231,2301,2381,2578,2809,2980,3029,3037,3057,
        3128,3443,3702,4000,4343,4848,5000,5117,5250,5450,5600,
        5814,6080,6173,6988,7000,7001,7005,7071,7144,7145,7510,
        7770,7777,7778,7779,8000,8001,8008,8014,8015,8020,8028,
        8040,8080,8081,8082,8085,8088,8090,8118,8123,8180,8181,
        8182,8222,8243,8280,8300,8333,8344,8400,8443,8500,8509,
        8787,8800,8888,8899,8983,9000,9002,9060,9080,9090,9091,
        9111,9290,9443,9447,9710,9788,9999,10000,11371,12601,13014,
        15489,19980,29991,33300,34412,34443,34444,40007,41080,44449,
        50000,50002,51423,53331,55252,55555,56712};
    
    //Port values for Oracle ports was specified on the The Official Blog of the World Leading Open-Source IDS/IPS Snort.
    //https://blog.snort.org/2011/01/new-rule-pack-and-check-your-snortconf_04.html
    private static int[] FILE_DATA_PORTS = {36,80,81,82,83,84,85,86,87,88,89,90,110,143,311,383,555,591,
        593,631,801,808,818,901,972,1158,1220,1414,1533,1741,
        1830,1942,2231,2301,2381,2578,2809,2980,3029,3037,3057,
        3128,3443,3702,4000,4343,4848,5000,5117,5250,5450,5600,
        5814,6080,6173,6988,7000,7001,7005,7071,7144,7145,7510,
        7770,7777,7778,7779,8000,8001,8008,8014,8015,8020,8028,
        8040,8080,8081,8082,8085,8088,8090,8118,8123,8180,8181,
        8182,8222,8243,8280,8300,8333,8344,8400,8443,8500,8509,
        8787,8800,8888,8899,8983,9000,9002,9060,9080,9090,9091,
        9111,9290,9443,9447,9710,9788,9999,10000,11371,12601,13014,
        15489,19980,29991,33300,34412,34443,34444,40007,41080,44449,
        50000,50002,51423,53331,55252,55555,56712};
    
    //Port values for Oracle ports was specified on the The Official Blog of the World Leading Open-Source IDS/IPS Snort.
    //https://blog.snort.org/2011/01/new-rule-pack-and-check-your-snortconf_04.html
    private static int[] ORACLE_PORTS = {1024};

    //Port values for Oracle ports was specified on the The Official Blog of the World Leading Open-Source IDS/IPS Snort.
    //https://blog.snort.org/2011/01/new-rule-pack-and-check-your-snortconf_04.html
    private static int[] FTP_PORTS = {21, 2100, 3535};

    //Port values for Oracle ports was specified on the The Official Blog of the World Leading Open-Source IDS/IPS Snort.
    //https://blog.snort.org/2011/01/new-rule-pack-and-check-your-snortconf_04.html
    private static int[] SSH_PORTS = {22};

    //Port values for Oracle ports was specified on the The Official Blog of the World Leading Open-Source IDS/IPS Snort.
    //https://blog.snort.org/2011/01/new-rule-pack-and-check-your-snortconf_04.html
    private static int[] SIP_PORTS = {5060, 5061, 5600};

    public static int[] getHTTP_PORTS() {
        return HTTP_PORTS;
    }

    public static int[] getFILE_DATA_PORTS() {
        return FILE_DATA_PORTS;
    }

    public static int[] getORACLE_PORTS() {
        return ORACLE_PORTS;
    }

    public static int[] getFTP_PORTS() {
        return FTP_PORTS;
    }

    public static int[] getSSH_PORTS() {
        return SSH_PORTS;
    }

    public static int[] getSIP_PORTS() {
        return SIP_PORTS;
    }
}