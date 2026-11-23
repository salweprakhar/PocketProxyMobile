package com.pocketproxy.lab;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/** In-memory queue for manually intercepted plain HTTP requests. */
public final class InterceptStore {
    private static final long WAIT_SECONDS = 45;
    private static final int MAX_PENDING = 24;
    private static final LinkedHashMap<Long, PendingRequest> PENDING = new LinkedHashMap<>();
    private static final AtomicLong NEXT_ID = new AtomicLong(1);
    public static volatile boolean enabled = false;

    private InterceptStore() {}

    public static final class PendingRequest {
        public final long id = NEXT_ID.getAndIncrement();
        public final String originalMethod;
        public final String originalUrl;
        public final CountDownLatch decision = new CountDownLatch(1);
        public volatile String method;
        public volatile String url;
        public volatile String headers;
        public volatile String body;
        public volatile boolean dropped;
        public volatile boolean timedOut;

        private PendingRequest(String method, String url, String headers, String body) {
            this.originalMethod = method;
            this.originalUrl = url;
            this.method = method;
            this.url = url;
            this.headers = headers;
            this.body = body;
        }
    }

    public static PendingRequest awaitDecision(String method, String url, String headers, String body) {
        if (!enabled) return null;
        PendingRequest request = new PendingRequest(method, url, headers, body);
        synchronized (PENDING) {
            if (!enabled || PENDING.size() >= MAX_PENDING) return null;
            PENDING.put(request.id, request);
        }
        TrafficStore.changed();
        try {
            if (!request.decision.await(WAIT_SECONDS, TimeUnit.SECONDS)) {
                request.timedOut = true;
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            request.timedOut = true;
        } finally {
            synchronized (PENDING) {
                PENDING.remove(request.id);
            }
            TrafficStore.changed();
        }
        return request;
    }

    public static List<PendingRequest> snapshot() {
        synchronized (PENDING) {
            return new ArrayList<>(PENDING.values());
        }
    }

    public static void forward(PendingRequest request, String method, String url,
                               String headers, String body) {
        synchronized (request) {
            if (request.decision.getCount() == 0) return;
            request.method = method;
            request.url = url;
            request.headers = headers;
            request.body = body;
            request.decision.countDown();
        }
        TrafficStore.changed();
    }

    public static void drop(PendingRequest request) {
        synchronized (request) {
            if (request.decision.getCount() == 0) return;
            request.dropped = true;
            request.decision.countDown();
        }
        TrafficStore.changed();
    }

    public static void passPending() {
        List<PendingRequest> requests = snapshot();
        for (PendingRequest request : requests) {
            synchronized (request) {
                request.decision.countDown();
            }
        }
        TrafficStore.changed();
    }

    public static void dropPending() {
        List<PendingRequest> requests = snapshot();
        for (PendingRequest request : requests) {
            synchronized (request) {
                if (request.decision.getCount() == 0) continue;
                request.dropped = true;
                request.decision.countDown();
            }
        }
        TrafficStore.changed();
    }
}
