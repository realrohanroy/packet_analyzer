package org.example.pcap;

import java.io.*;

public class PcapReader {

    private DataInputStream file;
    private PcapGlobalHeader globalHeader = new PcapGlobalHeader();
    private boolean needsByteSwap = false;

    private static final long PCAP_MAGIC_NATIVE = 0xa1b2c3d4L;
    private static final long PCAP_MAGIC_SWAPPED = 0xd4c3b2a1L;

    public boolean open(String filename) {

        try {

            file = new DataInputStream(
                    new BufferedInputStream(
                            new FileInputStream(filename)));

            globalHeader.magicNumber = Integer.toUnsignedLong(file.readInt());

            if (globalHeader.magicNumber == PCAP_MAGIC_NATIVE) {
                needsByteSwap = false;
            }
            else if (globalHeader.magicNumber == PCAP_MAGIC_SWAPPED) {
                needsByteSwap = true;
            }
            else {
                System.out.println("Invalid PCAP magic number");
                return false;
            }

            globalHeader.versionMajor = maybeSwap16(file.readUnsignedShort());
            globalHeader.versionMinor = maybeSwap16(file.readUnsignedShort());
            globalHeader.thisZone = maybeSwap32(file.readInt());
            globalHeader.sigfigs = Integer.toUnsignedLong(maybeSwap32(file.readInt()));
            globalHeader.snaplen = Integer.toUnsignedLong(maybeSwap32(file.readInt()));
            globalHeader.network = Integer.toUnsignedLong(maybeSwap32(file.readInt()));

            System.out.println("Opened PCAP file");
            System.out.println("Version: " +
                    globalHeader.versionMajor + "." +
                    globalHeader.versionMinor);

            return true;

        } catch (Exception e) {
            System.out.println("Error opening file: " + e);
            return false;
        }
    }

    public void close() {
        try {
            if (file != null) file.close();
        } catch (Exception ignored) {}
    }

    public boolean readNextPacket(RawPacket packet) {

        try {

            packet.header.tsSec =
                    Integer.toUnsignedLong(maybeSwap32(file.readInt()));

            packet.header.tsUsec =
                    Integer.toUnsignedLong(maybeSwap32(file.readInt()));

            packet.header.inclLen =
                    Integer.toUnsignedLong(maybeSwap32(file.readInt()));

            packet.header.origLen =
                    Integer.toUnsignedLong(maybeSwap32(file.readInt()));

            int len = (int) packet.header.inclLen;

            if (len <= 0 || len > globalHeader.snaplen) {
                return false;
            }

            packet.data = new byte[len];
            file.readFully(packet.data);

            return true;

        } catch (EOFException e) {
            return false;
        } catch (Exception e) {
            System.out.println("Read error: " + e);
            return false;
        }
    }

    private int maybeSwap16(int value) {

        if (!needsByteSwap) return value;

        return ((value & 0xFF00) >> 8) |
               ((value & 0x00FF) << 8);
    }

    private int maybeSwap32(int value) {

        if (!needsByteSwap) return value;

        return ((value >>> 24)) |
               ((value >> 8) & 0xFF00) |
               ((value << 8) & 0xFF0000) |
               ((value << 24));
    }

    public PcapGlobalHeader getGlobalHeader() {
        return globalHeader;
    }
}