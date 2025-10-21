package com.sorf.IsolatedSFTP.util;

import org.jetbrains.annotations.NotNull;

import java.util.Optional;
import java.util.concurrent.*;

public class AsyncTask {
    private static AsyncTask instance = new AsyncTask();
    private ExecutorService executorService;

    private AsyncTask() {
        this.executorService = Executors.newCachedThreadPool() ;
    }

    public static @NotNull AsyncTask getInstance() {
        return instance;
    }

    public void invoke(@NotNull Runnable runnable) {
        if (!executorService.isShutdown()) {
            executorService.execute(runnable);
        }
    }

    public void invokeWithResult(@NotNull FutureTask<Optional> task) {
        if (!executorService.isShutdown()) {
            executorService.submit(task);
        }
    }

    public void stop() {
        this.executorService.shutdown();
    }

}

