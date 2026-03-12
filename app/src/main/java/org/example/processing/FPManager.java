package org.example.processing;

import org.example.concurrency.ThreadSafeQueue;
import org.example.rules.RuleManager;
import org.example.core.Types.PacketJob;

import java.util.ArrayList;
import java.util.List;

public class FPManager {

    private List<FastPathProcessor> fps = new ArrayList<>();

    public FPManager(int numFps,
                     RuleManager ruleManager,
                     PacketOutputCallback callback) {

        for (int i = 0; i < numFps; i++) {

            fps.add(new FastPathProcessor(
                    i,
                    ruleManager,
                    callback));
        }

        System.out.println("[FPManager] Created "
                + numFps + " fast path processors");
    }

    public void startAll() {

        for (FastPathProcessor fp : fps)
            fp.start();
    }

    public void stopAll() {

        for (FastPathProcessor fp : fps)
            fp.stop();
    }

    public FastPathProcessor getFP(int id) {
        return fps.get(id);
    }

    public ThreadSafeQueue<PacketJob> getFPQueue(int id) {
        return fps.get(id).getInputQueue();
    }

    public List<ThreadSafeQueue<PacketJob>> getQueues() {

        List<ThreadSafeQueue<PacketJob>> q = new ArrayList<>();

        for (FastPathProcessor fp : fps)
            q.add(fp.getInputQueue());

        return q;
    }

    public String generateClassificationReport() {
        return "\nClassification Report Generation missing in Java Port";
    }

}