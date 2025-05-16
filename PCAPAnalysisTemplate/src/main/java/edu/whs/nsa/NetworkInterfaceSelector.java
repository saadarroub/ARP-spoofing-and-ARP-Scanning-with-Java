package edu.whs.nsa;

import java.util.List;
import java.util.Scanner;

import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

public class NetworkInterfaceSelector {
    
    public static PcapNetworkInterface selectNetworkInterface() throws PcapNativeException {
        // Get available network interfaces
        List<PcapNetworkInterface> devices = Pcaps.findAllDevs();
        if (devices == null || devices.isEmpty()) {
            System.err.println("No network devices found.");
            return null;
        }

        // Display available devices
        System.out.println("Available network devices:");
        for (int i = 1; i < devices.size(); i++) {
            PcapNetworkInterface nif = devices.get(i);
            System.out.println(i + ": " + nif.getDescription()
                    + "\n    with name: " + nif.getName()
                    + "\n    with IP: " + nif.getAddresses());
        }

        // User selects interface
        Scanner scanner = new Scanner(System.in);
        System.out.print("\nEnter the index of the network interface to use: ");
        int selectedIndex = scanner.nextInt();
        if (selectedIndex < 0 || selectedIndex >= devices.size()) {
            System.err.println("Invalid index.");
            return null;
        }
        
        return devices.get(selectedIndex);
    }
} 