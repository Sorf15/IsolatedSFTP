package com.sorf.IsolatedSFTP.util;

import java.text.SimpleDateFormat;
import java.time.Duration;
import java.util.Date;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class TimeUtil {

    private static final SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm");

    /**
     * @return formatted time: "14:05:24"
     */
    public static String getTime() {
        return String.format("%tT", new Date());
    }

    public static String getTime(Date date) {
        return String.format("%tT", date);
    }

    public static String getFullTime() {
        return format.format(new Date());
    }

    public static String getFullTime(Date date) {
        return format.format(date);
    }

    public static Duration parseDuration(String timeString) {
        Pattern pattern = Pattern.compile("(\\d+)([wdhms])");
        Matcher matcher = pattern.matcher(timeString);

        Duration duration = Duration.ZERO;

        while (matcher.find()) {
            long amount = Long.parseLong(matcher.group(1));
            String unit = matcher.group(2);

            switch (unit) {
                case "w":
                    duration = duration.plusDays(amount * 7);
                    break;
                case "d":
                    duration = duration.plusDays(amount);
                    break;
                case "h":
                    duration = duration.plusHours(amount);
                    break;
                case "m":
                    duration = duration.plusMinutes(amount);
                    break;
                case "s":
                    duration = duration.plusSeconds(amount);
                    break;
            }
        }
        return duration;
    }
}

