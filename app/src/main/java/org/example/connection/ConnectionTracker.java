package org.example.connection;

import org.example.core.Types;

import java.util.*;
import java.util.function.Consumer;

public class ConnectionTracker {

    private final int fpId;
    private final int maxConnections;

    private final Map<Types.FiveTuple, Types.Connection> connections = new HashMap<>();

    private long totalSeen = 0;
    private long classifiedCount = 0;
    private long blockedCount = 0;

    public ConnectionTracker(int fpId, int maxConnections) {
        this.fpId = fpId;
        this.maxConnections = maxConnections;
    }

    public ConnectionTracker(int fpId) {
        this(fpId, 100000);
    }

    // ----------------------------------------------------
    // Connection retrieval
    // ----------------------------------------------------

    public Types.Connection getOrCreateConnection(Types.FiveTuple tuple) {

        Types.Connection conn = connections.get(tuple);

        if (conn != null) {
            return conn;
        }

        if (connections.size() >= maxConnections) {
            evictOldest();
        }

        conn = new Types.Connection();
        conn.tuple = tuple;
        conn.state = Types.ConnectionState.NEW;
        conn.firstSeen = System.currentTimeMillis();
        conn.lastSeen = conn.firstSeen;

        connections.put(tuple, conn);
        totalSeen++;

        return conn;
    }

    public Types.Connection getConnection(Types.FiveTuple tuple) {

        Types.Connection conn = connections.get(tuple);

        if (conn != null) {
            return conn;
        }

        return connections.get(tuple.reverse());
    }

    // ----------------------------------------------------
    // Update connection
    // ----------------------------------------------------

    public void updateConnection(Types.Connection conn, int packetSize, boolean outbound) {

        if (conn == null) return;

        conn.lastSeen = System.currentTimeMillis();

        if (outbound) {
            conn.packetsOut++;
            conn.bytesOut += packetSize;
        } else {
            conn.packetsIn++;
            conn.bytesIn += packetSize;
        }
    }

    public void classifyConnection(Types.Connection conn, Types.AppType app, String sni) {

        if (conn == null) return;

        if (conn.state != Types.ConnectionState.CLASSIFIED) {

            conn.appType = app;
            conn.sni = sni;
            conn.state = Types.ConnectionState.CLASSIFIED;

            classifiedCount++;
        }
    }

    public void blockConnection(Types.Connection conn) {

        if (conn == null) return;

        conn.state = Types.ConnectionState.BLOCKED;
        conn.action = Types.PacketAction.DROP;

        blockedCount++;
    }

    public void closeConnection(Types.FiveTuple tuple) {

        Types.Connection conn = connections.get(tuple);

        if (conn != null) {
            conn.state = Types.ConnectionState.CLOSED;
        }
    }

    // ----------------------------------------------------
    // Cleanup
    // ----------------------------------------------------

    public int cleanupStale(long timeoutMillis) {

        long now = System.currentTimeMillis();

        int removed = 0;

        Iterator<Map.Entry<Types.FiveTuple, Types.Connection>> it =
                connections.entrySet().iterator();

        while (it.hasNext()) {

            Map.Entry<Types.FiveTuple, Types.Connection> entry = it.next();

            Types.Connection conn = entry.getValue();

            long age = now - conn.lastSeen;

            if (age > timeoutMillis || conn.state == Types.ConnectionState.CLOSED) {

                it.remove();
                removed++;
            }
        }

        return removed;
    }

    // ----------------------------------------------------
    // Stats
    // ----------------------------------------------------

    public int getActiveCount() {
        return connections.size();
    }

    public static class TrackerStats {

        public long activeConnections;
        public long totalConnectionsSeen;
        public long classifiedConnections;
        public long blockedConnections;
    }

    public TrackerStats getStats() {

        TrackerStats stats = new TrackerStats();

        stats.activeConnections = connections.size();
        stats.totalConnectionsSeen = totalSeen;
        stats.classifiedConnections = classifiedCount;
        stats.blockedConnections = blockedCount;

        return stats;
    }

    // ----------------------------------------------------
    // Reporting helpers
    // ----------------------------------------------------

    public List<Types.Connection> getAllConnections() {
        return new ArrayList<>(connections.values());
    }

    public void forEach(Consumer<Types.Connection> callback) {

        for (Types.Connection conn : connections.values()) {
            callback.accept(conn);
        }
    }

    // ----------------------------------------------------
    // Maintenance
    // ----------------------------------------------------

    public void clear() {
        connections.clear();
    }

    private void evictOldest() {

        if (connections.isEmpty()) return;

        Types.FiveTuple oldestKey = null;
        long oldestTime = Long.MAX_VALUE;

        for (Map.Entry<Types.FiveTuple, Types.Connection> e : connections.entrySet()) {

            if (e.getValue().lastSeen < oldestTime) {
                oldestTime = e.getValue().lastSeen;
                oldestKey = e.getKey();
            }
        }

        if (oldestKey != null) {
            connections.remove(oldestKey);
        }
    }
}