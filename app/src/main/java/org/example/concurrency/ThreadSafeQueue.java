package org.example.concurrency;

import java.util.LinkedList;
import java.util.Optional;
import java.util.Queue;

public class ThreadSafeQueue<T> {

    private final Queue<T> queue = new LinkedList<>();
    private final int maxSize;

    private boolean shutdown = false;

    public ThreadSafeQueue(int maxSize) {
        this.maxSize = maxSize;
    }

    // Push item (blocks if queue full)
    public synchronized void push(T item) throws InterruptedException {

        while (queue.size() >= maxSize && !shutdown) {
            wait();
        }

        if (shutdown) return;

        queue.add(item);
        notifyAll();
    }

    // Non blocking push
    public synchronized boolean tryPush(T item) {

        if (queue.size() >= maxSize || shutdown) {
            return false;
        }

        queue.add(item);
        notifyAll();
        return true;
    }

    // Pop item (blocks if empty)
    public synchronized Optional<T> pop() throws InterruptedException {

        while (queue.isEmpty() && !shutdown) {
            wait();
        }

        if (queue.isEmpty()) {
            return Optional.empty();
        }

        T item = queue.poll();
        notifyAll();
        return Optional.of(item);
    }

    // Pop with timeout
    public synchronized Optional<T> popWithTimeout(long timeoutMillis) throws InterruptedException {

        if (queue.isEmpty() && !shutdown) {
            wait(timeoutMillis);
        }

        if (queue.isEmpty()) {
            return Optional.empty();
        }

        T item = queue.poll();
        notifyAll();
        return Optional.of(item);
    }

    // Check if empty
    public synchronized boolean empty() {
        return queue.isEmpty();
    }

    // Current size
    public synchronized int size() {
        return queue.size();
    }

    // Shutdown queue
    public synchronized void shutdown() {

        shutdown = true;
        notifyAll();
    }

    public synchronized boolean isShutdown() {
        return shutdown;
    }
}