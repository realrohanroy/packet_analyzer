package org.example.engine;

import org.example.core.Types.*;
import org.example.concurrency.ThreadSafeQueue;

import java.util.*;

public class LBManager {

    private List<LoadBalancer> lbs = new ArrayList<>();

    private int fpsPerLb;

    public LBManager(int numLbs,
                     int fpsPerLb,
                     List<ThreadSafeQueue<PacketJob>> fpQueues) {

        this.fpsPerLb = fpsPerLb;

        for (int lbId = 0; lbId < numLbs; lbId++) {

            List<ThreadSafeQueue<PacketJob>> lbFpQueues =
                    new ArrayList<>();

            int fpStart = lbId * fpsPerLb;

            for (int i = 0; i < fpsPerLb; i++)
                lbFpQueues.add(fpQueues.get(fpStart + i));

            lbs.add(new LoadBalancer(lbId, lbFpQueues, fpStart));
        }

        System.out.println("[LBManager] Created "
                + numLbs + " load balancers, "
                + fpsPerLb + " FPs each");
    }

    public void startAll() {

        for (LoadBalancer lb : lbs)
            lb.start();
    }

    public void stopAll() {

        for (LoadBalancer lb : lbs)
            lb.stop();
    }

    public LoadBalancer getLBForPacket(FiveTuple tuple) {

        int hash = tuple.hashCode();

        if (hash < 0)
            hash = -hash;

        int lbIndex = hash % lbs.size();

        return lbs.get(lbIndex);
    }

    public AggregatedStats getAggregatedStats() {

        AggregatedStats stats = new AggregatedStats();

        for (LoadBalancer lb : lbs) {

            LoadBalancer.LBStats s = lb.getStats();

            stats.totalReceived += s.packetsReceived;
            stats.totalDispatched += s.packetsDispatched;
        }

        return stats;
    }

    public static class AggregatedStats {

        public long totalReceived;
        public long totalDispatched;
    }
}
