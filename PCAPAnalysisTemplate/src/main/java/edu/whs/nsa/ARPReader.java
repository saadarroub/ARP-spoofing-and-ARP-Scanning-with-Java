package edu.whs.nsa;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.TimeoutException;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.Packet;

public class ARPReader {

    /**
     * Maximum packet size to capture (64KB)
     * Standard Ethernet frame size (2^16 bytes)
     */
    private static final int SNAP_LEN = 65536; 

    /**
     * Packet capture timeout in milliseconds
     * Standard value balancing response time and CPU usage
     */
    private static final int TIMEOUT = 10;   
    private static final int MAX_PACKETS = 500; // Capture limit

    public static void main(String[] args) throws IOException, PcapNativeException, NotOpenException {
        // Set path to Npcap libraries (adjust if needed)
        System.setProperty("org.pcap4j.core.pcapLibName", "C:\\Windows\\System32\\Npcap\\wpcap.dll");
        System.setProperty("org.pcap4j.core.packetLibName", "C:\\Windows\\System32\\Npcap\\Packet.dll");

            /**
             * Find all available network interfaces on the system 
             * by using the NetworkInterfaceSelector class
             */
            PcapNetworkInterface selectedNif = NetworkInterfaceSelector.selectNetworkInterface();
            if (selectedNif == null) {
                return;
            }

            /**
             * Opens network interface for packet capture
             * @param SNAP_LEN - Max packet size (65536 bytes)
             * @param PROMISCUOUS - Capture all network packets
             * @param TIMEOUT - Read timeout in milliseconds
             */
            try (PcapHandle handle = selectedNif.openLive(SNAP_LEN, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, TIMEOUT)) {

                System.out.println("\n--- Ready to capture ARP packets ---");  
                // Create a LinkedHashMap to store chronologically ordered ARP entries
                Map<String, String> arpTable = new LinkedHashMap<>();
                int packetCount = 0;
                long endTime = System.currentTimeMillis() + 300000; // Run for about 5 minutes

                // Capture loop: runs for 5 minutes or until MAX_PACKETS is reached
                while (System.currentTimeMillis() < endTime && packetCount <= MAX_PACKETS) {
                    try {
                        // Get next packet from the network interface
                        Packet packet = handle.getNextPacketEx();

                        // filter ARP packets and extract ARP packet and its header information
                        if (packet.contains(ArpPacket.class)) {
                        ArpPacket arp = packet.get(ArpPacket.class);
                        String srcIp = arp.getHeader().getSrcProtocolAddr().getHostAddress();
                        String srcMac = arp.getHeader().getSrcHardwareAddr().toString();
                        
                        // Store IP-MAC mapping in our table
                        arpTable.put(srcIp, srcMac);
                        packetCount++;
                    }
                    } catch (TimeoutException e) {
                        // No packet this round
                    } 
                }

            // Display results
            System.out.println("\nARP-Table:");
            System.out.println("IP Address          MAC Address");
            System.out.println("----------------------------------------------");
            for (Map.Entry<String, String> entry : arpTable.entrySet()) {
                System.out.println(entry.getKey() + "         " + entry.getValue());
            }
        }
    }
}
