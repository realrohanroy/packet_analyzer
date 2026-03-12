package org.example.core;

public class PacketParser {

    public static boolean parse(byte[] data, ParsedPacket parsed) {

        int offset = 0;

        if (!parseEthernet(data, parsed)) {
            return false;
        }

        offset = 14;

        if (parsed.etherType == EtherType.IPv4) {

            int ipHeaderLen = parseIPv4(data, offset, parsed);
            if (ipHeaderLen == -1) return false;

            offset += ipHeaderLen;

            if (parsed.protocol == Protocol.TCP) {

                int tcpLen = parseTCP(data, offset, parsed);
                if (tcpLen == -1) return false;

                offset += tcpLen;

            } else if (parsed.protocol == Protocol.UDP) {

                int udpLen = parseUDP(data, offset, parsed);
                if (udpLen == -1) return false;

                offset += udpLen;
            }
        }

        if (offset < data.length) {

            parsed.payloadLength = data.length - offset;
            parsed.payloadData = new byte[parsed.payloadLength];

            System.arraycopy(data, offset,
                    parsed.payloadData, 0,
                    parsed.payloadLength);
        }

        return true;
    }

    // Ethernet parsing
    private static boolean parseEthernet(byte[] data, ParsedPacket parsed) {

        if (data.length < 14) return false;

        parsed.destMac = macToString(data, 0);
        parsed.srcMac = macToString(data, 6);

        parsed.etherType =
                ((data[12] & 0xff) << 8) |
                (data[13] & 0xff);

        return true;
    }

    // IPv4 parsing
    private static int parseIPv4(byte[] data, int offset, ParsedPacket parsed) {

        if (data.length < offset + 20) return -1;

        int versionIhl = data[offset] & 0xff;

        parsed.ipVersion = (versionIhl >> 4) & 0x0F;
        int ihl = versionIhl & 0x0F;

        int headerLen = ihl * 4;

        if (parsed.ipVersion != 4) return -1;

        parsed.ttl = data[offset + 8] & 0xff;
        parsed.protocol = data[offset + 9] & 0xff;

        parsed.srcIp = ipToString(data, offset + 12);
        parsed.destIp = ipToString(data, offset + 16);

        parsed.srcIpInt = ((data[offset + 12] & 0xff)) |
                          ((data[offset + 13] & 0xff) << 8) |
                          ((data[offset + 14] & 0xff) << 16) |
                          ((data[offset + 15] & 0xff) << 24);

        parsed.destIpInt = ((data[offset + 16] & 0xff)) |
                           ((data[offset + 17] & 0xff) << 8) |
                           ((data[offset + 18] & 0xff) << 16) |
                           ((data[offset + 19] & 0xff) << 24);

        parsed.hasIp = true;

        return headerLen;
    }

    // TCP parsing
    private static int parseTCP(byte[] data, int offset, ParsedPacket parsed) {

        if (data.length < offset + 20) return -1;

        parsed.srcPort =
                ((data[offset] & 0xff) << 8) |
                (data[offset + 1] & 0xff);

        parsed.destPort =
                ((data[offset + 2] & 0xff) << 8) |
                (data[offset + 3] & 0xff);

        parsed.seqNumber =
                ((long)(data[offset+4] & 0xff) << 24) |
                ((long)(data[offset+5] & 0xff) << 16) |
                ((long)(data[offset+6] & 0xff) << 8) |
                (data[offset+7] & 0xff);

        parsed.ackNumber =
                ((long)(data[offset+8] & 0xff) << 24) |
                ((long)(data[offset+9] & 0xff) << 16) |
                ((long)(data[offset+10] & 0xff) << 8) |
                (data[offset+11] & 0xff);

        int dataOffset = (data[offset + 12] >> 4) & 0x0F;
        int headerLen = dataOffset * 4;

        parsed.tcpFlags = data[offset + 13] & 0xff;
        parsed.hasTcp = true;

        return headerLen;
    }

    // UDP parsing
    private static int parseUDP(byte[] data, int offset, ParsedPacket parsed) {

        if (data.length < offset + 8) return -1;

        parsed.srcPort =
                ((data[offset] & 0xff) << 8) |
                (data[offset + 1] & 0xff);

        parsed.destPort =
                ((data[offset + 2] & 0xff) << 8) |
                (data[offset + 3] & 0xff);

        parsed.hasUdp = true;

        return 8;
    }

    // Helpers

    public static String macToString(byte[] data, int start) {

        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < 6; i++) {

            if (i > 0) sb.append(":");

            sb.append(String.format("%02x",
                    data[start + i] & 0xff));
        }

        return sb.toString();
    }

    public static String ipToString(byte[] data, int start) {

        return (data[start] & 0xff) + "." +
               (data[start+1] & 0xff) + "." +
               (data[start+2] & 0xff) + "." +
               (data[start+3] & 0xff);
    }
}