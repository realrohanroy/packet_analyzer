package org.example.pcap;


public class RawPacket {

    public PcapPacketHeader header;
    public byte[] data;

    public RawPacket() {
        header = new PcapPacketHeader();
    }
}