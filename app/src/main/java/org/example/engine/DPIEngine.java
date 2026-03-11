package org.example.engine;

import org.example.core.Types;
import org.example.pcap.PcapReader;
import org.example.core.PacketParser;
import org.example.rules.RuleManager;

import org.example.pcap.RawPacket;
import org.example.core.ParsedPacket;

import java.io.FileOutputStream;
import java.io.IOException;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

public class DPIEngine {

    public static class Config {

        public int numLoadBalancers = 2;
        public int fpsPerLb = 2;
        public int queueSize = 10000;
        public String rulesFile = "";
        public boolean verbose = false;
    }

    private final Config config;

    private RuleManager ruleManager;

    private ExecutorService fpPool;
    private ExecutorService lbPool;

    private BlockingQueue<Types.PacketJob> outputQueue;

    private FileOutputStream outputFile;

    private AtomicBoolean running = new AtomicBoolean(false);

    private Thread readerThread;

    public DPIEngine(Config config) {

        this.config = config;
        this.outputQueue = new ArrayBlockingQueue<>(config.queueSize);
    }

    public boolean initialize() {

        ruleManager = new RuleManager();

        if (!config.rulesFile.isEmpty()) {
            ruleManager.loadRules(config.rulesFile);
        }

        int totalFPs = config.numLoadBalancers * config.fpsPerLb;

        fpPool = Executors.newFixedThreadPool(totalFPs);
        lbPool = Executors.newFixedThreadPool(config.numLoadBalancers);

        System.out.println("[DPIEngine] Initialized");

        return true;
    }

    public void start() {

        running.set(true);

        startOutputThread();

        System.out.println("[DPIEngine] Started");
    }

    public void stop() {

        running.set(false);

        if (fpPool != null)
            fpPool.shutdownNow();

        if (lbPool != null)
            lbPool.shutdownNow();

        System.out.println("[DPIEngine] Stopped");
    }

    public boolean processFile(String inputFile, String outputFileName) {

        if (ruleManager == null)
            initialize();

        try {

            outputFile = new FileOutputStream(outputFileName);

        } catch (Exception e) {

            System.out.println("Cannot open output file");

            return false;
        }

        start();

        readerThread = new Thread(() -> readerThreadFunc(inputFile));

        readerThread.start();

        try {

            readerThread.join();

        } catch (InterruptedException e) {
        }

        stop();

        return true;
    }

    private void readerThreadFunc(String inputFile) {

        PcapReader reader = new PcapReader();

        if (!reader.open(inputFile)) {

            System.out.println("Cannot open PCAP");

            return;
        }

        RawPacket raw = new RawPacket();
        ParsedPacket parsed = new ParsedPacket();

        int packetId = 0;

        while (reader.readNextPacket(raw)) {

            if (!PacketParser.parse(raw.data, parsed))
                continue;

            if (!parsed.hasIp)
                continue;

            Types.PacketJob job = createPacketJob(raw, parsed, packetId++);

            dispatchToFastPath(job);
        }

        reader.close();
    }

    private void dispatchToFastPath(Types.PacketJob job) {

        fpPool.submit(() -> processPacket(job));
    }

    private void processPacket(Types.PacketJob job) {

        Types.AppType app = Types.AppType.UNKNOWN;

        String domain = "";

        RuleManager.BlockReason reason =
                ruleManager.shouldBlock(
                        job.tuple.srcIp,
                        job.tuple.dstPort,
                        app,
                        domain
                );

        if (reason != null) {

            return;
        }

        try {

            outputQueue.put(job);

        } catch (InterruptedException e) {
        }
    }

    private Types.PacketJob createPacketJob(

            RawPacket raw,
            ParsedPacket parsed,
            int id) {

        Types.PacketJob job = new Types.PacketJob();

        job.packetId = id;

        job.tuple.srcIp = parseIP(parsed.srcIp);
        job.tuple.dstIp = parseIP(parsed.destIp);
        job.tuple.srcPort = parsed.srcPort;
        job.tuple.dstPort = parsed.destPort;
        job.tuple.protocol = parsed.protocol;

        job.data = raw.data;

        return job;
    }

    private int parseIP(String ip) {

        String[] parts = ip.split("\\.");

        int result = 0;

        for (int i = 0; i < 4; i++)
            result |= Integer.parseInt(parts[i]) << (i * 8);

        return result;
    }

    private void startOutputThread() {

        Thread t = new Thread(() -> {

            while (running.get() || !outputQueue.isEmpty()) {

                try {

                    Types.PacketJob job = outputQueue.poll(
                            100,
                            TimeUnit.MILLISECONDS
                    );

                    if (job != null)
                        writePacket(job);

                } catch (Exception ignored) {
                }
            }

        });

        t.start();
    }

    private void writePacket(Types.PacketJob job) {

        try {

            outputFile.write(job.data);

        } catch (IOException e) {
        }
    }

    public RuleManager getRuleManager() {

        return ruleManager;
    }

}