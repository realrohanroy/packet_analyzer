package org.example.core;

import java.util.Optional;

public class SNIExtractor {

    private static final int CONTENT_TYPE_HANDSHAKE = 0x16;
    private static final int HANDSHAKE_CLIENT_HELLO = 0x01;
    private static final int EXTENSION_SNI = 0x0000;
    private static final int SNI_TYPE_HOSTNAME = 0x00;

    private static int readUint16BE(byte[] data, int offset) {
        return ((data[offset] & 0xff) << 8) | (data[offset + 1] & 0xff);
    }

    private static int readUint24BE(byte[] data, int offset) {
        return ((data[offset] & 0xff) << 16)
                | ((data[offset + 1] & 0xff) << 8)
                | (data[offset + 2] & 0xff);
    }

    public static boolean isTLSClientHello(byte[] payload, int length) {

        if (length < 9) return false;

        if ((payload[0] & 0xff) != CONTENT_TYPE_HANDSHAKE)
            return false;

        int version = readUint16BE(payload, 1);
        if (version < 0x0300 || version > 0x0304)
            return false;

        int recordLength = readUint16BE(payload, 3);
        if (recordLength > length - 5)
            return false;

        if ((payload[5] & 0xff) != HANDSHAKE_CLIENT_HELLO)
            return false;

        return true;
    }

    public static String extract(byte[] payload, int length) {

        if (!isTLSClientHello(payload, length))
            return null;

        int offset = 5;

        int handshakeLength = readUint24BE(payload, offset + 1);
        offset += 4;

        offset += 2;
        offset += 32;

        if (offset >= length) return null;

        int sessionLen = payload[offset] & 0xff;
        offset += 1 + sessionLen;

        if (offset + 2 > length) return null;

        int cipherLen = readUint16BE(payload, offset);
        offset += 2 + cipherLen;

        if (offset >= length) return null;

        int compLen = payload[offset] & 0xff;
        offset += 1 + compLen;

        if (offset + 2 > length) return null;

        int extensionsLen = readUint16BE(payload, offset);
        offset += 2;

        int extensionsEnd = Math.min(offset + extensionsLen, length);

        while (offset + 4 <= extensionsEnd) {

            int extType = readUint16BE(payload, offset);
            int extLen = readUint16BE(payload, offset + 2);
            offset += 4;

            if (offset + extLen > extensionsEnd)
                break;

            if (extType == EXTENSION_SNI) {

                if (extLen < 5)
                    break;

                int sniListLen = readUint16BE(payload, offset);

                int sniType = payload[offset + 2] & 0xff;
                int sniLen = readUint16BE(payload, offset + 3);

                if (sniType != SNI_TYPE_HOSTNAME)
                    break;

                if (sniLen > extLen - 5)
                    break;

                return new String(payload, offset + 5, sniLen);
            }

            offset += extLen;
        }

        return null;
    }
}