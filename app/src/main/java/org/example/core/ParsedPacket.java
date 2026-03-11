package org.example.core;

public class ParsedPacket {

    public long timestampSec;
    public long timestampUsec;

    // Ethernet
    public String srcMac;
    public String destMac;
    public int etherType;

    // IP
    public boolean hasIp = false;
    public int ipVersion;
    public String srcIp;
    public String destIp;
    public int protocol;
    public int ttl;

    // Transport
    public boolean hasTcp = false;
    public boolean hasUdp = false;

    public int srcPort;
    public int destPort;

    // TCP
    public int tcpFlags;
    public long seqNumber;
    public long ackNumber;

    // Payload
    public int payloadLength;
    public byte[] payloadData;
}

