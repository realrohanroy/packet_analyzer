package org.example.core;

import java.util.concurrent.atomic.AtomicLong;

public class Types {

    // ============================================================
    // FiveTuple (Flow Identifier)
    // ============================================================
    public static class FiveTuple {

        public int srcIp;
        public int dstIp;
        public int srcPort;
        public int dstPort;
        public int protocol;

        public FiveTuple() {}

        public FiveTuple(int srcIp, int dstIp, int srcPort, int dstPort, int protocol) {
            this.srcIp = srcIp;
            this.dstIp = dstIp;
            this.srcPort = srcPort;
            this.dstPort = dstPort;
            this.protocol = protocol;
        }

        public FiveTuple reverse() {
            return new FiveTuple(dstIp, srcIp, dstPort, srcPort, protocol);
        }

        @Override
        public boolean equals(Object o) {

            if (this == o) return true;
            if (!(o instanceof FiveTuple)) return false;

            FiveTuple other = (FiveTuple) o;

            return srcIp == other.srcIp &&
                    dstIp == other.dstIp &&
                    srcPort == other.srcPort &&
                    dstPort == other.dstPort &&
                    protocol == other.protocol;
        }

        @Override
        public int hashCode() {

            int result = srcIp;
            result = 31 * result + dstIp;
            result = 31 * result + srcPort;
            result = 31 * result + dstPort;
            result = 31 * result + protocol;

            return result;
        }

        public long getHash() {
            long h = 0;
            h ^= (srcIp & 0xFFFFFFFFL) + 0x9e3779b9L + (h << 6) + (h >>> 2);
            h ^= (dstIp & 0xFFFFFFFFL) + 0x9e3779b9L + (h << 6) + (h >>> 2);
            h ^= (srcPort & 0xFFFFL) + 0x9e3779b9L + (h << 6) + (h >>> 2);
            h ^= (dstPort & 0xFFFFL) + 0x9e3779b9L + (h << 6) + (h >>> 2);
            h ^= (protocol & 0xFFL) + 0x9e3779b9L + (h << 6) + (h >>> 2);
            return h;
        }

        @Override
        public String toString() {
            return srcIp + ":" + srcPort +
                    " -> " +
                    dstIp + ":" + dstPort +
                    " proto=" + protocol;
        }
    }

    // ============================================================
    // Application Type
    // ============================================================
    public enum AppType {

        UNKNOWN,
        HTTP,
        HTTPS,
        DNS,
        TLS,
        QUIC,

        GOOGLE,
        FACEBOOK,
        YOUTUBE,
        TWITTER,
        INSTAGRAM,
        NETFLIX,
        AMAZON,
        MICROSOFT,
        APPLE,
        WHATSAPP,
        TELEGRAM,
        TIKTOK,
        SPOTIFY,
        ZOOM,
        DISCORD,
        GITHUB,
        CLOUDFLARE
    }

    public static AppType sniToAppType(String sni) {
        if (sni == null || sni.isEmpty()) return AppType.UNKNOWN;
        
        String lower = sni.toLowerCase();
        
        if (lower.contains("google") || lower.contains("gstatic") || 
            lower.contains("googleapis") || lower.contains("ggpht") || lower.contains("gvt1")) return AppType.GOOGLE;
        if (lower.contains("youtube") || lower.contains("ytimg") || lower.contains("youtu.be")) return AppType.YOUTUBE;
        if (lower.contains("facebook") || lower.contains("fbcdn") || lower.contains("fb.com")) return AppType.FACEBOOK;
        if (lower.contains("instagram") || lower.contains("cdninstagram")) return AppType.INSTAGRAM;
        if (lower.contains("whatsapp") || lower.contains("wa.me")) return AppType.WHATSAPP;
        if (lower.contains("twitter") || lower.contains("twimg") || lower.contains("x.com")) return AppType.TWITTER;
        if (lower.contains("netflix") || lower.contains("nflxvideo")) return AppType.NETFLIX;
        if (lower.contains("amazon") || lower.contains("aws") || lower.contains("cloudfront")) return AppType.AMAZON;
        if (lower.contains("microsoft") || lower.contains("azure") || lower.contains("live.com")) return AppType.MICROSOFT;
        if (lower.contains("apple") || lower.contains("icloud")) return AppType.APPLE;
        if (lower.contains("telegram") || lower.contains("t.me")) return AppType.TELEGRAM;
        if (lower.contains("tiktok") || lower.contains("bytedance")) return AppType.TIKTOK;
        if (lower.contains("spotify") || lower.contains("scdn.co")) return AppType.SPOTIFY;
        if (lower.contains("zoom")) return AppType.ZOOM;
        if (lower.contains("discord")) return AppType.DISCORD;
        if (lower.contains("github")) return AppType.GITHUB;
        if (lower.contains("cloudflare") || lower.contains("cf-")) return AppType.CLOUDFLARE;
        
        return AppType.HTTPS;
    }

    // ============================================================
    // Connection State
    // ============================================================
    public enum ConnectionState {

        NEW,
        ESTABLISHED,
        CLASSIFIED,
        BLOCKED,
        CLOSED
    }

    // ============================================================
    // Packet Action
    // ============================================================
    public enum PacketAction {

        FORWARD,
        DROP,
        INSPECT,
        LOG_ONLY
    }

    // ============================================================
    // Connection Entry
    // ============================================================
    public static class Connection {

        public FiveTuple tuple;

        public ConnectionState state = ConnectionState.NEW;

        public AppType appType = AppType.UNKNOWN;

        public String sni = "";

        public long packetsIn = 0;
        public long packetsOut = 0;
        public long bytesIn = 0;
        public long bytesOut = 0;

        public long firstSeen;
        public long lastSeen;

        public PacketAction action = PacketAction.FORWARD;

        public boolean synSeen = false;
        public boolean synAckSeen = false;
        public boolean finSeen = false;

        public Connection() {
            firstSeen = System.currentTimeMillis();
            lastSeen = firstSeen;
        }
    }

    // ============================================================
    // Packet Job
    // ============================================================
    public static class PacketJob {

        public int packetId;

        public FiveTuple tuple;

        public byte[] data;

        public int ethOffset = 0;
        public int ipOffset = 0;
        public int transportOffset = 0;
        public int payloadOffset = 0;
        public int payloadLength = 0;
        public byte[] payloadData;

        public int tcpFlags = 0;

        public long tsSec;
        public long tsUsec;
    }

    // ============================================================
    // Statistics
    // ============================================================
    public static class DPIStats {

        public AtomicLong totalPackets = new AtomicLong();
        public AtomicLong totalBytes = new AtomicLong();

        public AtomicLong forwardedPackets = new AtomicLong();
        public AtomicLong droppedPackets = new AtomicLong();

        public AtomicLong tcpPackets = new AtomicLong();
        public AtomicLong udpPackets = new AtomicLong();
        public AtomicLong otherPackets = new AtomicLong();

        public AtomicLong activeConnections = new AtomicLong();
    }
}