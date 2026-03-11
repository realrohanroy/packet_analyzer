package org.example.rules;

import org.example.core.Types;

import java.io.*;
import java.util.*;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class RuleManager {

    private final Set<Integer> blockedIPs = new HashSet<>();
    private final Set<Types.AppType> blockedApps = new HashSet<>();
    private final Set<String> blockedDomains = new HashSet<>();
    private final List<String> domainPatterns = new ArrayList<>();
    private final Set<Integer> blockedPorts = new HashSet<>();

    private final ReentrantReadWriteLock ipLock = new ReentrantReadWriteLock();
    private final ReentrantReadWriteLock appLock = new ReentrantReadWriteLock();
    private final ReentrantReadWriteLock domainLock = new ReentrantReadWriteLock();
    private final ReentrantReadWriteLock portLock = new ReentrantReadWriteLock();

    // ================= IP BLOCKING =================

    public void blockIP(int ip) {
        ipLock.writeLock().lock();
        try {
            blockedIPs.add(ip);
            System.out.println("[RuleManager] Blocked IP: " + ipToString(ip));
        } finally {
            ipLock.writeLock().unlock();
        }
    }

    public void blockIP(String ip) {
        blockIP(parseIP(ip));
    }

    public void unblockIP(int ip) {
        ipLock.writeLock().lock();
        try {
            blockedIPs.remove(ip);
        } finally {
            ipLock.writeLock().unlock();
        }
    }

    public boolean isIPBlocked(int ip) {
        ipLock.readLock().lock();
        try {
            return blockedIPs.contains(ip);
        } finally {
            ipLock.readLock().unlock();
        }
    }

    public List<String> getBlockedIPs() {
        ipLock.readLock().lock();
        try {
            List<String> list = new ArrayList<>();
            for (int ip : blockedIPs) {
                list.add(ipToString(ip));
            }
            return list;
        } finally {
            ipLock.readLock().unlock();
        }
    }

    // ================= APP BLOCKING =================

    public void blockApp(Types.AppType app) {
        appLock.writeLock().lock();
        try {
            blockedApps.add(app);
        } finally {
            appLock.writeLock().unlock();
        }
    }

    public boolean isAppBlocked(Types.AppType app) {
        appLock.readLock().lock();
        try {
            return blockedApps.contains(app);
        } finally {
            appLock.readLock().unlock();
        }
    }

    public List<Types.AppType> getBlockedApps() {
        appLock.readLock().lock();
        try {
            return new ArrayList<>(blockedApps);
        } finally {
            appLock.readLock().unlock();
        }
    }

    // ================= DOMAIN BLOCKING =================

    public void blockDomain(String domain) {
        domainLock.writeLock().lock();
        try {
            if (domain.contains("*")) {
                domainPatterns.add(domain);
            } else {
                blockedDomains.add(domain);
            }
        } finally {
            domainLock.writeLock().unlock();
        }
    }

    public boolean isDomainBlocked(String domain) {
        domainLock.readLock().lock();
        try {

            if (blockedDomains.contains(domain))
                return true;

            String lower = domain.toLowerCase();

            for (String pattern : domainPatterns) {

                String p = pattern.toLowerCase();

                if (domainMatchesPattern(lower, p))
                    return true;
            }

            return false;

        } finally {
            domainLock.readLock().unlock();
        }
    }

    public List<String> getBlockedDomains() {
        domainLock.readLock().lock();
        try {
            List<String> result = new ArrayList<>(blockedDomains);
            result.addAll(domainPatterns);
            return result;
        } finally {
            domainLock.readLock().unlock();
        }
    }

    // ================= PORT BLOCKING =================

    public void blockPort(int port) {
        portLock.writeLock().lock();
        try {
            blockedPorts.add(port);
        } finally {
            portLock.writeLock().unlock();
        }
    }

    public boolean isPortBlocked(int port) {
        portLock.readLock().lock();
        try {
            return blockedPorts.contains(port);
        } finally {
            portLock.readLock().unlock();
        }
    }

    // ================= RULE CHECK =================

    public BlockReason shouldBlock(
            int srcIp,
            int dstPort,
            Types.AppType app,
            String domain) {

        if (isIPBlocked(srcIp)) {
            return new BlockReason(BlockReason.Type.IP, ipToString(srcIp));
        }

        if (isPortBlocked(dstPort)) {
            return new BlockReason(BlockReason.Type.PORT, String.valueOf(dstPort));
        }

        if (isAppBlocked(app)) {
            return new BlockReason(BlockReason.Type.APP, app.name());
        }

        if (domain != null && !domain.isEmpty() && isDomainBlocked(domain)) {
            return new BlockReason(BlockReason.Type.DOMAIN, domain);
        }

        return null;
    }

    // ================= FILE PERSISTENCE =================

    public boolean saveRules(String filename) {

        try (PrintWriter writer = new PrintWriter(new FileWriter(filename))) {

            writer.println("[BLOCKED_IPS]");
            for (String ip : getBlockedIPs())
                writer.println(ip);

            writer.println("\n[BLOCKED_APPS]");
            for (Types.AppType app : getBlockedApps())
                writer.println(app.name());

            writer.println("\n[BLOCKED_DOMAINS]");
            for (String domain : getBlockedDomains())
                writer.println(domain);

            writer.println("\n[BLOCKED_PORTS]");
            portLock.readLock().lock();
            try {
                for (int port : blockedPorts)
                    writer.println(port);
            } finally {
                portLock.readLock().unlock();
            }

            return true;

        } catch (IOException e) {
            return false;
        }
    }

    public boolean loadRules(String filename) {

        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {

            String line;
            String section = "";

            while ((line = reader.readLine()) != null) {

                if (line.isEmpty())
                    continue;

                if (line.startsWith("[")) {
                    section = line;
                    continue;
                }

                switch (section) {

                    case "[BLOCKED_IPS]":
                        blockIP(line);
                        break;

                    case "[BLOCKED_APPS]":
                        blockApp(Types.AppType.valueOf(line));
                        break;

                    case "[BLOCKED_DOMAINS]":
                        blockDomain(line);
                        break;

                    case "[BLOCKED_PORTS]":
                        blockPort(Integer.parseInt(line));
                        break;
                }
            }

            return true;

        } catch (IOException e) {
            return false;
        }
    }

    // ================= HELPERS =================

    private static int parseIP(String ip) {

        String[] parts = ip.split("\\.");
        int result = 0;

        for (int i = 0; i < 4; i++) {
            result |= Integer.parseInt(parts[i]) << (i * 8);
        }

        return result;
    }

    private static String ipToString(int ip) {

        return ((ip >> 0) & 0xFF) + "." +
               ((ip >> 8) & 0xFF) + "." +
               ((ip >> 16) & 0xFF) + "." +
               ((ip >> 24) & 0xFF);
    }

    private static boolean domainMatchesPattern(String domain, String pattern) {

        if (pattern.startsWith("*.")) {

            String suffix = pattern.substring(1);

            if (domain.endsWith(suffix))
                return true;

            return domain.equals(pattern.substring(2));
        }

        return false;
    }

    // ================= SUPPORT CLASSES =================

    public static class BlockReason {

        public enum Type {
            IP, APP, DOMAIN, PORT
        }

        public Type type;
        public String detail;

        public BlockReason(Type type, String detail) {
            this.type = type;
            this.detail = detail;
        }
    }

}