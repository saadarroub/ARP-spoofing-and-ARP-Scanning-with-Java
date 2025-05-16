package edu.whs.nsa;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashSet;

/**
 * This class contains several helper methods to compute all IP addresses in a given subnet.
 */
public class IpRangeCalculator {

    /**
     * Provides a simple example on how to use the class.
     *
     * @param args - None
     * @throws UnknownHostException - If the example input is not a valid CIDR string (e.g., 10.0.2.26/20).
     */
    public static void main(String[] args) throws UnknownHostException {
        // Example CIDR input
        String ipCidrNotation = "10.0.2.26/20";
        // Compute all IPs
        HashSet<String> ipRange = generateIpRange(ipCidrNotation);
        // Print all IPs in the subnet
        System.out.println("IP range for " + ipCidrNotation + ":\n" + ipRange);
    }

    /**
     * Computes all IP addresses that are part of the given subnet.
     *
     * @param ipCidrNotation - IP address and subnet mask in CIDR notation (e.g., 10.0.2.26/20).
     * @return - A HasSet of all IP addresses in the subnet.
     * @throws UnknownHostException - If the provided IP has the wrong format.
     */
    public static HashSet<String> generateIpRange(String ipCidrNotation) throws UnknownHostException {
        System.out.println("Computing all IPs for the subnet " + ipCidrNotation);
        String[] parts = ipCidrNotation.split("/");
        String ip = parts[0];
        int prefixLength = Integer.parseInt(parts[1]);

        // Convert IP to integer
        int ipAddress = ipToInt(InetAddress.getByName(ip));
        int subnetMask = ~((1 << (32 - prefixLength)) - 1);

        // Calculate the network address
        int networkAddress = ipAddress & subnetMask;

        // Calculate the broadcast address
        int broadcastAddress = networkAddress | ~subnetMask;

        // Generate all IPs in the range
        HashSet<String> ipRange = new HashSet<>();
        for (int i = networkAddress; i <= broadcastAddress; i++) {
            ipRange.add(intToIp(i));
        }

        return ipRange;
    }

    /**
     * Converts a standard subnet mask (e.g., 255.255.255.0) into the suffix for a CIDR notation of an IP address
     *
     * @param netmask - The standard subnet mask
     * @return - The suffix of a CIDR notation for the given subnet mask (e.g., /24).
     */
    public static int convertNetmaskToCIDR(InetAddress netmask) {
        // get the subnet mask from the InetAddress object
        byte[] netmaskBytes = netmask.getAddress();

        int cidr = 0;
        boolean zero = false;

        // Loop oder all octets (i.e., 1s in the subnet mask) and compute the CIDR notation suffix.
        for (byte b : netmaskBytes) {
            int mask = 0x80;

            for (int i = 0; i < 8; i++) {
                int result = b & mask;
                if (result == 0) {
                    zero = true;
                } else if (zero) {
                    throw new IllegalArgumentException("Invalid subnet mask.");
                } else {
                    cidr++;
                }
                mask >>>= 1;
            }
        }
        return cidr;
    }

    /**
     * A  helper method to convert an IP address into an integer.
     *
     * @param ip The IP Address that should be converted.
     * @return - The Integer representation of teh IP address.
     */
    private static int ipToInt(InetAddress ip) {
        byte[] bytes = ip.getAddress();
        int result = 0;
        for (byte b : bytes) {
            result = (result << 8) | (b & 0xFF);
        }
        return result;
    }

    /**
     * Helper method to convert an integer into a string representation of teh IP address.
     *
     * @param ip The IP address (as integer).
     * @return - The IP address formatted as string.
     */
    private static String intToIp(int ip) {
        return ((ip >> 24) & 0xFF) + "." +
                ((ip >> 16) & 0xFF) + "." +
                ((ip >> 8) & 0xFF) + "." +
                (ip & 0xFF);
    }
}
