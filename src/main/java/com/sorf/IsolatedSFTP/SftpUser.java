package com.sorf.IsolatedSFTP;

import com.sorf.IsolatedSFTP.util.Logger;
import com.sorf.IsolatedSFTP.util.Reference;
import com.sorf.IsolatedSFTP.util.TimeUtil;

import java.io.File;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Optional;

public class SftpUser {
    private final String username;
    private String pass;
    private final boolean admin;
    private final Date creation;
    private Duration duration;
    private final Path homeDir;
    private boolean inf = false;
    private boolean suspended = false;

    public SftpUser(String username, String pass, boolean admin, String duration, Path path) {
        String cUsername = username.trim(), cPass = pass.trim();
        if (cUsername.isEmpty() || cPass.isEmpty()) {
            Logger.error("Username or password is a blank field");
            throw new IllegalArgumentException();
        }

        this.username = username;
        this.pass = pass;
        this.creation = new Date();
        this.homeDir = path;
        if (this.username.equals(Reference.ADMIN_USERNAME)) {
            this.inf = true;
            this.duration = Duration.ZERO;
            this.admin = true;
        } else {
            this.admin = admin;
            if (duration.equals("inf")) {
                this.inf = true;
                this.duration = Duration.ZERO;
            } else {
                this.duration = TimeUtil.parseDuration(duration);
            }
        }

    }

    public SftpUser(String username, String pass, String duration) {
        this(username, pass, false, duration, new File(Reference.PATH, username).getAbsoluteFile().toPath());
    }

    public SftpUser(String username, String pass, Path path) {
        this(username, pass, true, "1d", path);
    }

    public SftpUser(String username, String pass) {
        this(username, pass, false, "1d", new File(Reference.PATH, username).getAbsoluteFile().toPath());
    }

    public String getUsername() {
        return username;
    }

    public String getPass() {
        return pass;
    }

    public Date getCreation() {
        return creation;
    }

    public Duration getDuration() {
        return duration;
    }

    public void setDuration(Duration duration) {
        this.duration = duration;
    }

    public boolean isSuspended() {
        return suspended;
    }

    public void setSuspended(boolean suspended) {
        this.suspended = suspended;
    }

    public void setPass(String pass) {
        this.pass = pass;
    }

    public boolean isAdmin() {
        return admin;
    }

    public Path getHomeDir() {
        return homeDir;
    }

    public boolean isInf() {
        return inf;
    }

    public void setInf(boolean inf) {
        this.inf = inf;
    }

    public boolean update() {
        if (inf) return false;
        if (username.equals(Reference.ADMIN_USERNAME)) return false;
        return creation.toInstant().plusSeconds(duration.getSeconds()).isBefore(Instant.now());
    }

    @Override
    public String toString() {
        return "SftpUser{" +
                "username='" + username + '\'' +
                ", pass='" + pass + '\'' +
                ", admin=" + admin +
                ", creation=" + creation +
                ", duration=" + duration +
                ", homeDir=" + homeDir +
                ", inf=" + inf +
                ", suspended=" + suspended +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof SftpUser)) return false;

        SftpUser user = (SftpUser) o;

        return getUsername().equals(user.getUsername());
    }

    @Override
    public int hashCode() {
        return getUsername().hashCode();
    }

    public static boolean validateUser(String username, String pass, List<SftpUser> userList) {
        Optional<SftpUser> sftpUserOptional = userList.stream().filter(sftpUser -> sftpUser.username.equals(username)).findAny();
        return sftpUserOptional.map(sftpUser -> sftpUser.pass.equals(pass) && !sftpUser.isSuspended()).orElse(false);
    }
}
