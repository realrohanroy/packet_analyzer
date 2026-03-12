package org.example.processing;

import org.example.connection.ConnectionTracker;
import org.example.concurrency.ThreadSafeQueue;
import org.example.rules.RuleManager;
import org.example.core.Types.*;
import org.example.core.Types;
import org.example.core.SNIExtractor;
import org.example.core.HTTPHostExtractor;
import org.example.core.DNSExtractor;

import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

public class FastPathProcessor implements Runnable {

    private int fpId;

    private ThreadSafeQueue<PacketJob> inputQueue =
            new ThreadSafeQueue<>(10000);

    private ConnectionTracker connTracker;

    private RuleManager ruleManager;

    private PacketOutputCallback outputCallback;

    private Thread thread;

    private AtomicBoolean running = new AtomicBoolean(false);

    private AtomicLong packetsProcessed = new AtomicLong();
    private AtomicLong packetsForwarded = new AtomicLong();
    private AtomicLong packetsDropped = new AtomicLong();
    private AtomicLong sniExtractions = new AtomicLong();
    private AtomicLong classificationHits = new AtomicLong();

    public FastPathProcessor(int id,
                             RuleManager ruleManager,
                             PacketOutputCallback callback) {

        this.fpId = id;
        this.ruleManager = ruleManager;
        this.outputCallback = callback;

        this.connTracker = new ConnectionTracker(id, 100000);
    }

    public void start() {

        if (running.get()) return;

        running.set(true);

        thread = new Thread(this, "FP-" + fpId);
        thread.start();

        System.out.println("[FP" + fpId + "] Started");
    }

    public void stop() {

        running.set(false);

        inputQueue.shutdown();

        try {
            if (thread != null)
                thread.join();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        System.out.println("[FP" + fpId + "] Stopped (processed "
                + packetsProcessed.get() + " packets)");
    }

    public ThreadSafeQueue<PacketJob> getInputQueue() {
        return inputQueue;
    }

    public ConnectionTracker getConnectionTracker() {
        return connTracker;
    }

    public long getPacketsProcessed() {
        return packetsProcessed.get();
    }

    @Override
    public void run() {

        while (running.get()) {

            try {

                Optional<PacketJob> jobOpt =
                        inputQueue.popWithTimeout(100);

                if (jobOpt.isEmpty()) {

                    connTracker.cleanupStale(300000);
                    continue;
                }

                PacketJob job = jobOpt.get();

                packetsProcessed.incrementAndGet();

                PacketAction action = processPacket(job);

                if (outputCallback != null)
                    outputCallback.handle(job, action);

                if (action == PacketAction.DROP)
                    packetsDropped.incrementAndGet();
                else
                    packetsForwarded.incrementAndGet();

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private PacketAction processPacket(PacketJob job) {

        Connection conn =
                connTracker.getOrCreateConnection(job.tuple);

        if (conn == null)
            return PacketAction.FORWARD;

        connTracker.updateConnection(conn,
                job.data.length,
                true);

        if (job.tuple.protocol == 6)
            updateTCPState(conn, job.tcpFlags);

        if (conn.state == ConnectionState.BLOCKED)
            return PacketAction.DROP;

        if (conn.state != ConnectionState.CLASSIFIED
                && job.payloadLength > 0)
            inspectPayload(job, conn);

        return checkRules(job, conn);
    }

    private void inspectPayload(PacketJob job, Connection conn) {

        if (job.payloadLength == 0)
            return;

        if (tryExtractSNI(job, conn))
            return;

        if (tryExtractHTTPHost(job, conn))
            return;

        if (job.tuple.dstPort == 53
                || job.tuple.srcPort == 53) {

            String domain =
                    DNSExtractor.extractQuery(
                            job.payloadData,
                            job.payloadLength);

            if (domain != null) {
                connTracker.classifyConnection(
                        conn,
                        AppType.DNS,
                        domain);
            }
        }

        if (job.tuple.dstPort == 80)
            connTracker.classifyConnection(conn, AppType.HTTP, "");

        else if (job.tuple.dstPort == 443)
            connTracker.classifyConnection(conn, AppType.HTTPS, "");
    }

    private boolean tryExtractSNI(PacketJob job, Connection conn) {

        if (job.tuple.dstPort != 443)
            return false;

        String sni =
                SNIExtractor.extract(job.payloadData,
                        job.payloadLength);

        if (sni == null)
            return false;

        sniExtractions.incrementAndGet();

        AppType app = Types.sniToAppType(sni);

        connTracker.classifyConnection(conn, app, sni);

        if (app != AppType.UNKNOWN && app != AppType.HTTPS)
            classificationHits.incrementAndGet();

        return true;
    }

    private boolean tryExtractHTTPHost(PacketJob job, Connection conn) {

        if (job.tuple.dstPort != 80)
            return false;

        String host =
                HTTPHostExtractor.extract(
                        job.payloadData,
                        job.payloadLength);

        if (host == null)
            return false;

        AppType app = Types.sniToAppType(host);

        connTracker.classifyConnection(conn, app, host);

        if (app != AppType.UNKNOWN && app != AppType.HTTP)
            classificationHits.incrementAndGet();

        return true;
    }

    private PacketAction checkRules(PacketJob job, Connection conn) {

        if (ruleManager == null)
            return PacketAction.FORWARD;

        RuleManager.BlockReason reason =
                ruleManager.shouldBlock(
                        job.tuple.srcIp,
                        job.tuple.dstPort,
                        conn.appType,
                        conn.sni);

        if (reason == null)
            return PacketAction.FORWARD;

        System.out.println("[FP" + fpId + "] BLOCKED: "
                + reason.detail);

        connTracker.blockConnection(conn);

        return PacketAction.DROP;
    }

    private void updateTCPState(Connection conn, int flags) {

        int SYN = 0x02;
        int ACK = 0x10;
        int FIN = 0x01;
        int RST = 0x04;

        if ((flags & SYN) != 0) {
            if ((flags & ACK) != 0)
                conn.synAckSeen = true;
            else
                conn.synSeen = true;
        }

        if (conn.synSeen && conn.synAckSeen && (flags & ACK) != 0) {
            if (conn.state == ConnectionState.NEW)
                conn.state = ConnectionState.ESTABLISHED;
        }

        if ((flags & FIN) != 0)
            conn.finSeen = true;

        if ((flags & RST) != 0)
            conn.state = ConnectionState.CLOSED;

        if (conn.finSeen && (flags & ACK) != 0)
            conn.state = ConnectionState.CLOSED;
    }

}
