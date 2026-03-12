package org.example.engine;

import org.example.core.*;
import org.example.pcap.*;
import org.example.rules.RuleManager;
import org.example.processing.*;
import org.example.connection.*;

import org.example.concurrency.ThreadSafeQueue;

import java.io.FileOutputStream;
import java.io.IOException;
import java.util.concurrent.atomic.AtomicBoolean;

public class DPIEngine {

    private static final String H_LINE = "\u2550".repeat(62);
    private static final String V = "\u2551";
    private static final String BOX_TOP = "\u2554" + H_LINE + "\u2557";
    private static final String BOX_MID = "\u2560" + H_LINE + "\u2563";
    private static final String BOX_BOT = "\u255A" + H_LINE + "\u255D";

    public static class Config {

        public int numLoadBalancers = 2;
        public int fpsPerLb = 2;
        public int queueSize = 10000;

        public String rulesFile = "";
        public boolean verbose = false;
    }

    private Config config;

    private RuleManager ruleManager;
    private GlobalConnectionTable globalConnTable;

    private FPManager fpManager;
    private LBManager lbManager;

    private ThreadSafeQueue<Types.PacketJob> outputQueue;

    private Thread outputThread;
    private Thread readerThread;

    private FileOutputStream outputFile;

    private Types.DPIStats stats = new Types.DPIStats();

    private AtomicBoolean running = new AtomicBoolean(false);

    public DPIEngine(Config config) {

        this.config = config;
        this.outputQueue = new ThreadSafeQueue<>(config.queueSize);

        System.out.println(BOX_TOP);
        System.out.println(V + "              DPI ENGINE v2.0 (Multi-threaded)                " + V);
        System.out.println(BOX_MID);
        System.out.printf(V + " Load Balancers: %2d    FPs per LB: %2d    Total FPs: %2d        " + V + "\n",
                config.numLoadBalancers, config.fpsPerLb, (config.numLoadBalancers * config.fpsPerLb));
        System.out.println(BOX_BOT + "\n");
    }

    // --------------------------------------------------
    // Initialize
    // --------------------------------------------------

    public boolean initialize() {

        ruleManager = new RuleManager();

        if (config.rulesFile != null && !config.rulesFile.isEmpty()) {
            ruleManager.loadRules(config.rulesFile);
        }

        PacketOutputCallback callback = this::handleOutput;

        int totalFP = config.numLoadBalancers * config.fpsPerLb;

        fpManager = new FPManager(totalFP, ruleManager, callback);

        lbManager = new LBManager(
                config.numLoadBalancers,
                config.fpsPerLb,
                fpManager.getQueues()
        );

        globalConnTable = new GlobalConnectionTable(totalFP);

        for (int i = 0; i < totalFP; i++) {
            globalConnTable.registerTracker(
                    i,
                    fpManager.getFP(i).getConnectionTracker()
            );
        }

        System.out.println("[DPIEngine] Initialized successfully");

        return true;
    }

    // --------------------------------------------------
    // Start / Stop
    // --------------------------------------------------

    public void start() {

        if (running.get()) return;

        running.set(true);

        outputThread = new Thread(this::outputThreadFunc);
        outputThread.start();

        fpManager.startAll();
        lbManager.startAll();

        System.out.println("[DPIEngine] All threads started");
    }

    public void stop() {

        if (!running.get()) return;

        running.set(false);

        lbManager.stopAll();
        fpManager.stopAll();

        outputQueue.shutdown();

        try {
            if (outputThread != null) outputThread.join();
        } catch (InterruptedException ignored) {}

        System.out.println("[DPIEngine] All threads stopped");
    }

    // --------------------------------------------------
    // PCAP Processing
    // --------------------------------------------------

    public boolean processFile(String inputFile, String outputFilePath) {

        // Removed duplicate processing print to match C++
        if (ruleManager == null) {
            if (!initialize()) return false;
        }

        try {
            outputFile = new FileOutputStream(outputFilePath);
        } catch (IOException e) {
            System.err.println("Cannot open output file");
            return false;
        }

        start();

        readerThread = new Thread(() -> readerThreadFunc(inputFile));
        readerThread.start();

        try {
            readerThread.join();
        } catch (InterruptedException ignored) {}

        stop();

        try {
            outputFile.close();
        } catch (IOException ignored) {}

        System.out.print(generateReport());
        System.out.print(generateClassificationReport());

        return true;
    }

    // --------------------------------------------------
    // Reader Thread
    // --------------------------------------------------

    private void readerThreadFunc(String inputFile) {

        PcapReader reader = new PcapReader();

        if (!reader.open(inputFile)) {
            System.err.println("[Reader] Cannot open input file");
            return;
        }

        writeOutputHeader(reader.getGlobalHeader());
        System.out.println("\n[Reader] Processing packets...");

        RawPacket raw = new RawPacket();
        ParsedPacket parsed = new ParsedPacket();

        int packetId = 0;

        while (reader.readNextPacket(raw)) {

            if (!PacketParser.parse(raw.data, parsed)) continue;

            if (!parsed.hasIp || (!parsed.hasTcp && !parsed.hasUdp)) continue;

            Types.PacketJob job = createPacketJob(raw, parsed, packetId++);

            stats.totalPackets.incrementAndGet();
            stats.totalBytes.addAndGet(raw.data.length);

            if (parsed.hasTcp) stats.tcpPackets.incrementAndGet();
            else if (parsed.hasUdp) stats.udpPackets.incrementAndGet();

            LoadBalancer lb = lbManager.getLBForPacket(job.tuple);

            try {
                lb.getInputQueue().push(job);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }

        System.out.println("[Reader] Done reading " + packetId + " packets\n");
        reader.close();
    }

    // --------------------------------------------------
    // Packet Job Creation
    // --------------------------------------------------

    private Types.PacketJob createPacketJob(RawPacket raw, ParsedPacket parsed, int packetId) {

        Types.PacketJob job = new Types.PacketJob();

        job.packetId = packetId;
        job.tsSec = raw.header.tsSec;
        job.tsUsec = raw.header.tsUsec;

        job.tuple = new Types.FiveTuple(
                parsed.srcIpInt,
                parsed.destIpInt,
                parsed.srcPort,
                parsed.destPort,
                parsed.protocol
        );

        job.tcpFlags = parsed.tcpFlags;

        job.data = raw.data;

        job.ethOffset = 0;
        job.ipOffset = 14;

        job.payloadLength = parsed.payloadLength;
        job.payloadData = parsed.payloadData;

        return job;
    }

    // --------------------------------------------------
    // Output Thread
    // --------------------------------------------------

    private void outputThreadFunc() {

        while (running.get() || !outputQueue.empty()) {

            try {
                java.util.Optional<Types.PacketJob> jobOpt = outputQueue.popWithTimeout(100);
                if (jobOpt.isPresent()) writeOutputPacket(jobOpt.get());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    private void handleOutput(Types.PacketJob job, Types.PacketAction action) {

        if (action == Types.PacketAction.DROP) {
            stats.droppedPackets.incrementAndGet();
            return;
        }

        stats.forwardedPackets.incrementAndGet();
        try {
            outputQueue.push(job);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    // --------------------------------------------------
    // PCAP Writing
    // --------------------------------------------------

    private void writeOutputHeader(PcapGlobalHeader header) {

        try {
            outputFile.write(header.toBytes());
        } catch (IOException ignored) {}
    }

    private void writeOutputPacket(Types.PacketJob job) {

        try {

            PcapPacketHeader pktHeader = new PcapPacketHeader();

            pktHeader.tsSec = job.tsSec;
            pktHeader.tsUsec = job.tsUsec;
            pktHeader.inclLen = job.data.length;
            pktHeader.origLen = job.data.length;

            outputFile.write(pktHeader.toBytes());
            outputFile.write(job.data);

        } catch (IOException ignored) {}
    }

    // --------------------------------------------------
    // Reporting
    // --------------------------------------------------

    public String generateReport() {

        StringBuilder sb = new StringBuilder();
        sb.append(BOX_TOP).append("\n");
        sb.append(V).append("                      PROCESSING REPORT                       ").append(V).append("\n");
        sb.append(BOX_MID).append("\n");
        sb.append(String.format(V + " Total Packets:     %-25d                 " + V + "\n", stats.totalPackets.get()));
        sb.append(String.format(V + " Total Bytes:       %-25d                 " + V + "\n", stats.totalBytes.get()));
        sb.append(String.format(V + " TCP Packets:       %-25d                 " + V + "\n", stats.tcpPackets.get()));
        sb.append(String.format(V + " UDP Packets:       %-25d                 " + V + "\n", stats.udpPackets.get()));
        sb.append(BOX_MID).append("\n");
        sb.append(String.format(V + " Forwarded:         %-25d                 " + V + "\n", stats.forwardedPackets.get()));
        sb.append(String.format(V + " Dropped:           %-25d                 " + V + "\n", stats.droppedPackets.get()));
        sb.append(BOX_MID).append("\n");
        sb.append(V).append(" THREAD STATISTICS                                            ").append(V).append("\n");
        
        for (int i = 0; i < config.numLoadBalancers; i++) {
            long disp = lbManager.getLBs().get(i).getStats().packetsDispatched;
            sb.append(String.format(V + "   LB%d dispatched: %-25d                 " + V + "\n", i, disp));
        }
        
        int totalFPs = config.numLoadBalancers * config.fpsPerLb;
        for (int i = 0; i < totalFPs; i++) {
            long proc = fpManager.getFP(i).getPacketsProcessed();
            sb.append(String.format(V + "   FP%d processed:  %-25d                 " + V + "\n", i, proc));
        }
        sb.append(BOX_BOT).append("\n");
        return sb.toString();
    }

    public String generateClassificationReport() {
        GlobalConnectionTable.GlobalStats gstats = globalConnTable.getGlobalStats();
        
        long totalClassified = 0;
        long totalUnknown = 0;
        for (java.util.Map.Entry<Types.AppType, Long> entry : gstats.appDistribution.entrySet()) {
            if (entry.getKey() == Types.AppType.UNKNOWN) {
                totalUnknown += entry.getValue();
            } else {
                totalClassified += entry.getValue();
            }
        }
        long totalConns = totalClassified + totalUnknown;
        
        double classPct = totalConns > 0 ? (100.0 * totalClassified / totalConns) : 0;
        double unkPct = totalConns > 0 ? (100.0 * totalUnknown / totalConns) : 0;
        
        StringBuilder sb = new StringBuilder();
        sb.append(BOX_TOP).append("\n");
        sb.append(V).append("                 APPLICATION CLASSIFICATION REPORT            ").append(V).append("\n");
        sb.append(BOX_MID).append("\n");
        sb.append(String.format(V + " Total Connections:   %-39d " + V + "\n", totalConns));
        sb.append(String.format(V + " Classified:          %-10d (%-5.1f%%)                     " + V + "\n", totalClassified, classPct));
        sb.append(String.format(V + " Unidentified:        %-10d (%-5.1f%%)                     " + V + "\n", totalUnknown, unkPct));
        sb.append(BOX_MID).append("\n");
        sb.append(V).append("                    APPLICATION DISTRIBUTION                  ").append(V).append("\n");
        sb.append(BOX_MID).append("\n");
        
        java.util.List<java.util.Map.Entry<Types.AppType, Long>> sortedApps = new java.util.ArrayList<>(gstats.appDistribution.entrySet());
        sortedApps.sort((a, b) -> Long.compare(b.getValue(), a.getValue()));
        
        for (java.util.Map.Entry<Types.AppType, Long> entry : sortedApps) {
            double pct = totalConns > 0 ? (100.0 * entry.getValue() / totalConns) : 0;
            int barLen = (int) (pct / 5);
            String bar = "#".repeat(barLen);
            sb.append(String.format(V + " %-20s %3d %5.1f%% %-20s         " + V + "\n", entry.getKey().name(), entry.getValue(), pct, bar));
        }
        sb.append(BOX_BOT).append("\n");
        return sb.toString();
    }

    public void printStatus() {

        System.out.println(
                "Packets=" + stats.totalPackets.get() +
                " Forwarded=" + stats.forwardedPackets.get() +
                " Dropped=" + stats.droppedPackets.get()
        );
    }

    // --------------------------------------------------
    // Rules Wrapper Methods
    // --------------------------------------------------

    public void loadRules(String rulesFile) {
        if (ruleManager != null) ruleManager.loadRules(rulesFile);
    }

    public void blockIP(String ip) {
        if (ruleManager != null) {
            ruleManager.blockIP(ip);
            System.out.println("[Rules] Blocked IP: " + ip);
        }
    }

    public void blockApp(String appName) {
        if (ruleManager != null) {
            for (Types.AppType type : Types.AppType.values()) {
                if (type.name().equalsIgnoreCase(appName)) {
                    ruleManager.blockApp(type);
                    System.out.println("[Rules] Blocked app: " + type.name());
                    return;
                }
            }
        }
    }

    public void blockDomain(String domain) {
        if (ruleManager != null) {
            ruleManager.blockDomain(domain);
            System.out.println("[Rules] Blocked domain: " + domain);
        }
    }
}