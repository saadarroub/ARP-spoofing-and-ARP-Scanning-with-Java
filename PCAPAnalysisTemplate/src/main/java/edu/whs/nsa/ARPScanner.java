package edu.whs.nsa;

public class ARPScanner {

    /**
     * Template for Task 3.
     *
     * @param args - None
     */
    public static void main(String[] args) {
        // Load the pcap4j libraries
        // TODO: Adjust the path to the libraries, if needed.
        System.setProperty("org.pcap4j.core.pcapLibName", "C:\\Windows\\System32\\Npcap\\wpcap.dll");
        System.setProperty("org.pcap4j.core.packetLibName", "C:\\Windows\\System32\\Npcap\\Packet.dll");


        // 1. Start observing ARP responses (e.g., by reusing some of the code of Task 1).
        // 2. Get the IP address and subnet mask of the network device used for the analysis.
        // 3. Find all IPs in the subnet. Please have a look at the class IpRangeCalculator, which helps you with the calculations.
        // 4. Perform the ARP scan and log results
        // 5. Print the results of the ARP scan.

    }

}
