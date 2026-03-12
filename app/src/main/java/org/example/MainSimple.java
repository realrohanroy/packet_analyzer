package org.example;

import org.example.pcap.PcapReader;
import org.example.pcap.RawPacket;
import org.example.core.PacketParser;
import org.example.core.Types;
import org.example.core.SNIExtractor;

public class MainSimple {

    public static void main(String[] args) throws Exception {

        if (args.length < 1) {
            System.err.println("Usage: java MainSimple <pcap_file>");
            return;
        }

        PcapReader reader = new PcapReader();

        if (!reader.open(args[0])) {
            System.err.println("Failed to open PCAP");
            return;
        }

        RawPacket raw = new RawPacket();
        org.example.core.ParsedPacket parsed = new org.example.core.ParsedPacket();

        int count = 0;
        int tlsCount = 0;

        System.out.println("Processing packets...");

        while (reader.readNextPacket(raw)) {

            count++;

            if (!PacketParser.parse(raw.data, parsed))
                continue;

            if (!parsed.hasIp)
                continue;

            System.out.print(
                    "Packet " + count + ": "
                            + parsed.srcIp + ":" + parsed.srcPort
                            + " -> "
                            + parsed.destIp + ":" + parsed.destPort
            );

            // TLS check
            if (parsed.hasTcp && parsed.destPort == 443 && parsed.payloadLength > 0) {

                int payloadOffset = 14;

                int ipIhl = raw.data[14] & 0x0F;
                payloadOffset += ipIhl * 4;

                int tcpOffset = (raw.data[payloadOffset + 12] >> 4) & 0x0F;
                payloadOffset += tcpOffset * 4;

                if (payloadOffset < raw.data.length) {

                    int payloadLen = raw.data.length - payloadOffset;

                    byte[] payload = new byte[payloadLen];
                    System.arraycopy(raw.data, payloadOffset, payload, 0, payloadLen);

                    String sni = SNIExtractor.extract(payload, payloadLen);

                    if (sni != null) {
                        System.out.print(" [SNI: " + sni + "]");
                        tlsCount++;
                    }
                }
            }

            System.out.println();
        }

        System.out.println("\nTotal packets: " + count);
        System.out.println("SNI extracted: " + tlsCount);

        reader.close();
    }
}
