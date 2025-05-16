package edu.whs.nsa;

import java.io.File;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.Packet;

public class ARPSpoofingDetector {
   
    private static  final Map<String, Set<String>> ipToMacs = new HashMap<>();
    public static void main(String[] args) throws PcapNativeException, NotOpenException {
        // Load the pcap4j libraries
        System.setProperty("org.pcap4j.core.pcapLibName", "C:\\Windows\\System32\\Npcap\\wpcap.dll");
        System.setProperty("org.pcap4j.core.packetLibName", "C:\\Windows\\System32\\Npcap\\Packet.dll");

        // Get all pcap files from data directory
        File dataDir = new File("PCAPAnalysisTemplate/data");
        File[] pcapFiles = dataDir.listFiles((dir, name) -> name.endsWith(".pcap"));
        
        
        if (pcapFiles == null || pcapFiles.length == 0) {
            System.err.println("No PCAP files found in data directory");
            return;
        }

        int totalPackets = 0;

        // Process each PCAP file and filter ARP packets and store in a map
        for (File pcapFile : pcapFiles) {
            try (PcapHandle handle = Pcaps.openOffline(pcapFile.getPath())) {
                Packet packet;
                while ((packet = handle.getNextPacket()) != null) {
                    if (packet.contains(ArpPacket.class)) {
                        ArpPacket arp = packet.get(ArpPacket.class);
                        String ip = arp.getHeader().getSrcProtocolAddr().getHostAddress();
                        String mac = arp.getHeader().getSrcHardwareAddr().toString();
                        ipToMacs.computeIfAbsent(ip, k -> new HashSet<>()).add(mac);
                        totalPackets++;
                    }
                }
            }
        }

        // Print results 
        System.out.println("ARP packet filtering finished: " + totalPackets + " ARP packets found.");
        System.out.println("-------------------------------------");

        int suspiciousCount = 0;
        for (Map.Entry<String, Set<String>> entry : ipToMacs.entrySet()) {
            // Check if the IP address has more than one MAC address
            if (entry.getValue().size() > 1) {
                
                // Diese Überschrift soll nur einmal ganz am Anfang erscheinen 
                if (suspiciousCount == 0) {
                    System.out.println("Suspicious IP address found:");
                }
                // Print the IP address and the MAC addresses
                suspiciousCount++;
                System.out.println(suspiciousCount + "- IP address: " + entry.getKey());
                System.out.println(" Registered MAC addresses:");
                for (String mac : entry.getValue()) {
                    System.out.println("- " + mac);
                }
            }
        }

        // Print summary
        System.out.println("-------------------------------------");
        System.out.println("Summary:");
        System.out.println("Checked IP addresses: " + ipToMacs.size());
        System.out.println("Suspicious IP addresses: " + suspiciousCount);
    }
}