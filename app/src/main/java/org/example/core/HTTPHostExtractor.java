package org.example.core;

public class HTTPHostExtractor {

    public static boolean isHTTPRequest(byte[] payload, int length) {

        if (length < 4) return false;

        String[] methods = {"GET ", "POST", "PUT ", "HEAD", "DELE", "PATC", "OPTI"};

        String first = new String(payload, 0, 4);

        for (String m : methods) {
            if (first.startsWith(m))
                return true;
        }

        return false;
    }

    public static String extract(byte[] payload, int length) {

        if (!isHTTPRequest(payload, length))
            return null;

        for (int i = 0; i < length - 6; i++) {

            if ((payload[i] == 'H' || payload[i] == 'h')
                    && (payload[i + 1] == 'o' || payload[i + 1] == 'O')
                    && (payload[i + 2] == 's' || payload[i + 2] == 'S')
                    && (payload[i + 3] == 't' || payload[i + 3] == 'T')
                    && payload[i + 4] == ':') {

                int start = i + 5;

                while (start < length &&
                        (payload[start] == ' ' || payload[start] == '\t'))
                    start++;

                int end = start;

                while (end < length &&
                        payload[end] != '\r' &&
                        payload[end] != '\n')
                    end++;

                String host = new String(payload, start, end - start);

                int colon = host.indexOf(':');
                if (colon != -1)
                    host = host.substring(0, colon);

                return host;
            }
        }

        return null;
    }
}
