package org.example.core;

public class DNSExtractor {

    public static boolean isDNSQuery(byte[] payload, int length) {

        if (length < 12) return false;

        int flags = payload[2] & 0xff;

        if ((flags & 0x80) != 0)
            return false;

        int qdcount = ((payload[4] & 0xff) << 8) | (payload[5] & 0xff);

        return qdcount > 0;
    }

    public static String extractQuery(byte[] payload, int length) {

        if (!isDNSQuery(payload, length))
            return null;

        int offset = 12;

        StringBuilder domain = new StringBuilder();

        while (offset < length) {

            int labelLen = payload[offset] & 0xff;

            if (labelLen == 0)
                break;

            if (labelLen > 63)
                break;

            offset++;

            if (offset + labelLen > length)
                break;

            if (domain.length() > 0)
                domain.append('.');

            domain.append(new String(payload, offset, labelLen));

            offset += labelLen;
        }

        if (domain.length() == 0)
            return null;

        return domain.toString();
    }
}
