package org.example.pcap;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class PcapGlobalHeader {

    public long magicNumber;
    public int versionMajor;
    public int versionMinor;
    public int thisZone;
    public long sigfigs;
    public long snaplen;
    public long network;

    public byte[] toBytes() {
        ByteBuffer buf = ByteBuffer.allocate(24);
        buf.order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt((int) 0xa1b2c3d4);
        buf.putShort((short) versionMajor);
        buf.putShort((short) versionMinor);
        buf.putInt(thisZone);
        buf.putInt((int) sigfigs);
        buf.putInt((int) snaplen);
        buf.putInt((int) network);
        return buf.array();
    }
}
