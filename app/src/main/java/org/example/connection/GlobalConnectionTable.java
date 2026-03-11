package org.example.connection;

import org.example.core.Types.*;

import java.util.*;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class GlobalConnectionTable {

    private final List<ConnectionTracker> trackers;
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

    public GlobalConnectionTable(int numFPs) {
        trackers = new ArrayList<>(Collections.nCopies(numFPs, null));
    }

    // Register tracker for FP
    public void registerTracker(int fpId, ConnectionTracker tracker) {
        lock.writeLock().lock();
        try {
            trackers.set(fpId, tracker);
        } finally {
            lock.writeLock().unlock();
        }
    }

    public static class GlobalStats {
        public long totalActiveConnections;
        public long totalConnectionsSeen;

        public Map<AppType, Long> appDistribution = new HashMap<>();
        public List<Map.Entry<String, Long>> topDomains = new ArrayList<>();
    }

    public GlobalStats getGlobalStats() {

        lock.readLock().lock();
        try {

            GlobalStats stats = new GlobalStats();
            Map<String, Long> domainCounts = new HashMap<>();

            for (ConnectionTracker tracker : trackers) {

                if (tracker == null) continue;

                List<Connection> connections = tracker.getAllConnections();

                stats.totalActiveConnections += connections.size();

                for (Connection conn : connections) {

                    stats.totalConnectionsSeen++;

                    stats.appDistribution.merge(
                            conn.appType,
                            1L,
                            Long::sum
                    );

                    if (conn.sni != null && !conn.sni.isEmpty()) {
                        domainCounts.merge(conn.sni, 1L, Long::sum);
                    }
                }
            }

            // sort domains
            List<Map.Entry<String, Long>> sortedDomains =
                    new ArrayList<>(domainCounts.entrySet());

            sortedDomains.sort((a, b) -> Long.compare(b.getValue(), a.getValue()));

            stats.topDomains = sortedDomains.stream()
                    .limit(10)
                    .toList();

            return stats;

        } finally {
            lock.readLock().unlock();
        }
    }

    public String generateReport() {

        GlobalStats stats = getGlobalStats();

        StringBuilder sb = new StringBuilder();

        sb.append("\n=== Global Connection Report ===\n");
        sb.append("Active Connections: ").append(stats.totalActiveConnections).append("\n");
        sb.append("Total Seen: ").append(stats.totalConnectionsSeen).append("\n");

        sb.append("\nApplication Distribution:\n");

        for (Map.Entry<AppType, Long> entry : stats.appDistribution.entrySet()) {
            sb.append(entry.getKey()).append(": ").append(entry.getValue()).append("\n");
        }

        sb.append("\nTop Domains:\n");

        for (Map.Entry<String, Long> domain : stats.topDomains) {
            sb.append(domain.getKey()).append(": ").append(domain.getValue()).append("\n");
        }

        return sb.toString();
    }
}