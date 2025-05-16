package edu.whs.nsa;

import java.net.InetAddress;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;

import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.ArpHardwareType;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.MacAddress;

public class ARPScanner {
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
    private static final Map<String, String> deviceMap = new LinkedHashMap<>(); // store ip and mac here

    public static void main(String[] args) {
        try {
            // Set pcap4j library paths (adjust if needed)
            System.setProperty("org.pcap4j.core.pcapLibName", "C:\\Windows\\System32\\Npcap\\wpcap.dll");
            System.setProperty("org.pcap4j.core.packetLibName", "C:\\Windows\\System32\\Npcap\\Packet.dll");

            // Reuse network interface selection from Task 1
             /**
             * Find all available network interfaces on the system 
             * by using the NetworkInterfaceSelector class
             */
            PcapNetworkInterface selectedNif = NetworkInterfaceSelector.selectNetworkInterface();
            if (selectedNif == null) {
                return;
            }

            // Get local IP and subnet mask
            PcapAddress addr = selectedNif.getAddresses().get(0);
            InetAddress ipAddress = addr.getAddress();
            InetAddress netmask = addr.getNetmask();

            // calculate network range
            int cidr = IpRangeCalculator.convertNetmaskToCIDR(netmask);
            String ipCidrNotation = ipAddress.getHostAddress() + "/" + cidr;

            // Generate IPs in subnet
            System.out.println("\nScanning network: " + ipCidrNotation);
            System.out.println("-------------------------------------");
            HashSet<String> ipRange = IpRangeCalculator.generateIpRange(ipCidrNotation);
            System.out.println("Scanning " + ipRange.size() + " IP addresses...");

            // open network card to send/receive
            PcapHandle handle = selectedNif.openLive(SNAP_LEN, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, TIMEOUT);
            InetAddress srcIp = ipAddress;
            MacAddress srcMac = MacAddress.getByAddress(selectedNif.getLinkLayerAddresses().get(0).getAddress());

            // Send ARP requests to all IPs
            for (String targetIpStr : ipRange) {
                if (!targetIpStr.equals(srcIp.getHostAddress())) {
                    try {
                        // send arp request to target ip to see if someone there
                        sendArpRequest(handle, srcIp, srcMac, InetAddress.getByName(targetIpStr));
                        Thread.sleep(5); // wait little bit
                    } catch (Exception e) {
                        // something went wrong but keep going
                        continue;
                    }
                }
            }

            // Listen for ARP responses for 15 seconds
            System.out.println("\nListening for responses...");
            long endTime = System.currentTimeMillis() + 15000; // Scan for 15 seconds
            while (System.currentTimeMillis() < endTime) {
                try {
                    Packet packet = handle.getNextPacketEx();
                    if (packet.contains(ArpPacket.class)) {
                        ArpPacket arp = packet.get(ArpPacket.class);
                        String senderIp = arp.getHeader().getSrcProtocolAddr().getHostAddress();
                        String senderMac = arp.getHeader().getSrcHardwareAddr().toString();
                        deviceMap.put(senderIp, senderMac); // save what we found
                    }
                } catch (Exception e) {
                    // dont care just keep going
                }
            }

            // Output results
            System.out.println("\nDetected devices:");
            System.out.println("IP address          MAC address");
            System.out.println("----------------------------------------------");
            for (Map.Entry<String, String> entry : deviceMap.entrySet()) {
                System.out.printf(entry.getKey() + "          " + entry.getValue() + "\n");
            }
            System.out.println("-------------------------------------");
            System.out.println("Detected active devices: " + deviceMap.size());

            handle.close();
        } catch (Exception e) {
            System.out.println("ups something broke: " + e.getMessage());
        }
    }

    /**
     * Sends an ARP request to the specified target IP
     */
    private static void sendArpRequest(PcapHandle handle, InetAddress srcIp, MacAddress srcMac, InetAddress targetIp) 
            throws Exception {
        MacAddress broadcast = MacAddress.getByName("FF:FF:FF:FF:FF:FF");

        // make arp packet
        ArpPacket.Builder arpBuilder = new ArpPacket.Builder()
                .hardwareType(ArpHardwareType.ETHERNET)
                .protocolType(EtherType.IPV4)
                .hardwareAddrLength((byte) MacAddress.SIZE_IN_BYTES)
                .protocolAddrLength((byte) 4)
                .operation(ArpOperation.REQUEST)
                .srcHardwareAddr(srcMac)
                .srcProtocolAddr(srcIp)
                .dstHardwareAddr(broadcast)
                .dstProtocolAddr(targetIp);

        // wrap in ethernet frame
        EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder()
                .dstAddr(broadcast)
                .srcAddr(srcMac)
                .type(EtherType.ARP)
                .payloadBuilder(arpBuilder)
                .paddingAtBuild(true);

        // send it
        handle.sendPacket(etherBuilder.build());
    }
}
