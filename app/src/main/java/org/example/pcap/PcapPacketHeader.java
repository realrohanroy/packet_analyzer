package org.example.pcap;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class PcapPacketHeader {

    public long tsSec;
    public long tsUsec;
    public long inclLen;
    public long origLen;

    public byte[] toBytes() {
        ByteBuffer buf = ByteBuffer.allocate(16);
        buf.order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt((int) tsSec);
        buf.putInt((int) tsUsec);
        buf.putInt((int) inclLen);
        buf.putInt((int) origLen);
        return buf.array();
    }
}
