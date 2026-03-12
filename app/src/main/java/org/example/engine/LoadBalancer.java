package org.example.engine;

import org.example.core.Types.*;
import org.example.concurrency.ThreadSafeQueue;

import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

public class LoadBalancer implements Runnable {

    private int lbId;
    private int fpStartId;
    private int numFps;

    private ThreadSafeQueue<PacketJob> inputQueue =
            new ThreadSafeQueue<>(10000);

    private List<ThreadSafeQueue<PacketJob>> fpQueues;

    private AtomicLong packetsReceived = new AtomicLong();
    private AtomicLong packetsDispatched = new AtomicLong();

    private List<Long> perFpCounts;

    private AtomicBoolean running = new AtomicBoolean(false);
    private Thread thread;

    public LoadBalancer(int lbId,
                        List<ThreadSafeQueue<PacketJob>> fpQueues,
                        int fpStartId) {

        this.lbId = lbId;
        this.fpQueues = fpQueues;
        this.fpStartId = fpStartId;
        this.numFps = fpQueues.size();

        this.perFpCounts = new ArrayList<>();
        for (int i = 0; i < numFps; i++)
            perFpCounts.add(0L);
    }

    public void start() {

        if (running.get())
            return;

        running.set(true);

        thread = new Thread(this);
        thread.start();

        System.out.println("[LB" + lbId + "] Started (serving FP"
                + fpStartId + "-FP" + (fpStartId + numFps - 1) + ")");
    }

    public void stop() {

        if (!running.get())
            return;

        running.set(false);
        inputQueue.shutdown();

        try {
            thread.join();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        System.out.println("[LB" + lbId + "] Stopped");
    }

    public ThreadSafeQueue<PacketJob> getInputQueue() {
        return inputQueue;
    }

    @Override
    public void run() {

        while (running.get()) {

            try {
                Optional<PacketJob> jobOpt = inputQueue.popWithTimeout(100);

                if (!jobOpt.isPresent())
                    continue;

                PacketJob job = jobOpt.get();

                packetsReceived.incrementAndGet();

                int fpIndex = selectFP(job.tuple);

                fpQueues.get(fpIndex).push(job);

                packetsDispatched.incrementAndGet();

                perFpCounts.set(fpIndex,
                        perFpCounts.get(fpIndex) + 1);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    private int selectFP(FiveTuple tuple) {

        long hash = tuple.getHash();

        return (int) Long.remainderUnsigned(hash, numFps);
    }

    public LBStats getStats() {

        LBStats stats = new LBStats();

        stats.packetsReceived = packetsReceived.get();
        stats.packetsDispatched = packetsDispatched.get();
        stats.perFpPackets = perFpCounts;

        return stats;
    }

    public static class LBStats {

        public long packetsReceived;
        public long packetsDispatched;
        public List<Long> perFpPackets;
    }
}
