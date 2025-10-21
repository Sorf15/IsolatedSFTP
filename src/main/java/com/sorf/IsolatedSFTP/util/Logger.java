package com.sorf.IsolatedSFTP.util;

import org.jetbrains.annotations.NotNull;

public class Logger {
    private static final String RESET = "\033[0m";  // Text Reset
    private static final String RED = "\033[0;31m";     // RED
    private static final String YELLOW = "\033[0;33m";  // YELLOW
    private static final String CYAN = "\033[0;36m";    // CYAN

    public static void debug(@NotNull String message, Object... objects) {
        System.out.printf(CYAN + "[DEBUG/" + Thread.currentThread().getName() + "]"+ getTime() + message + RESET + "%n", objects);
    }

    public static void info(@NotNull String message, Object... objects) {
        System.out.printf("["+TimeUtil.getTime() + "] " +  message + "%n", objects);
        //System.out.printf("[INFO]" + getTime() + message + "%n", objects);
    }
    public static void warn(@NotNull String message, Object... objects) {
        System.out.printf(YELLOW + "[WARN/" + Thread.currentThread().getName() + "]" + getTime() + message + RESET + "%n", objects);
    }

    public static void error(@NotNull String message, Object... objects) {
        System.out.printf(RED + "[ERROR/" + Thread.currentThread().getName() + "]" + getTime() + message + RESET + "%n", objects);
    }

    public static String getTime() {
        return " " + TimeUtil.getTime() + " ";
    }

}
