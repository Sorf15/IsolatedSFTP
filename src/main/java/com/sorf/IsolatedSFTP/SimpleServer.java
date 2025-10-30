package com.sorf.IsolatedSFTP;

import com.sorf.IsolatedSFTP.util.Reference;
import org.apache.sshd.common.file.virtualfs.VirtualFileSystemFactory;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.UserAuthFactory;
import org.apache.sshd.server.auth.password.PasswordAuthenticator;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.server.shell.ProcessShellCommandFactory;
import org.apache.sshd.server.subsystem.SubsystemFactory;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

public class SimpleServer {

    private SshServer server;
    private List<UserAuthFactory> userAuthFactories = new ArrayList<>();
    private List<SftpUser> users = Collections.synchronizedList(new ArrayList<>());
    private VirtualFileSystemFactory fileSystem;
    public List<String> loadedUsers = new ArrayList<>();

    public SimpleServer(int port, @NotNull Path defaultHomeDir) {
        this.server = SshServer.setUpDefaultServer();
        this.server.setPort(port);
        this.server.setKeyPairProvider(new SimpleGeneratorHostKeyProvider(Paths.get("hostkey.ser")));
        this.fileSystem = new VirtualFileSystemFactory(defaultHomeDir);
        this.server.setFileSystemFactory(fileSystem);
        this.server.setCommandFactory(new ProcessShellCommandFactory());
        this.users.add(new SftpUser(Reference.SUPER_ADMIN_USERNAME, Reference.SUPER_ADMIN_PASS,
                Reference.PATH2));
    }

    public SshServer getServer() {
        return server;
    }

    public List<SftpUser> getUsers() {
        return users;
    }

    public void setUserAuthFactories(List<UserAuthFactory> userAuthFactories) {
        this.userAuthFactories = userAuthFactories;
    }

    public void setUserAuthFactories(UserAuthFactory userAuthFactories) {
        this.userAuthFactories.clear();
        this.userAuthFactories.add(userAuthFactories);
    }

    public void addUserAuthFactories(List<UserAuthFactory> userAuthFactories) {
        this.userAuthFactories.addAll(userAuthFactories);
    }

    public void addUserAuthFactories(UserAuthFactory userAuthFactories) {
        this.userAuthFactories.add(userAuthFactories);
    }

    public void setPasswordAuthenticator(PasswordAuthenticator passwordAuthenticator) {
        this.server.setPasswordAuthenticator(passwordAuthenticator);
    }

    public void setSubsystemFactories(SubsystemFactory factories) {
        this.server.setSubsystemFactories(Collections.singletonList(factories));
    }

    public void loadUser(String username, String pass) {
        this.loadUser(new SftpUser(username, pass));
    }

    public void loadUser(String username, String pass, String duration) {
        this.loadUser(new SftpUser(username, pass, duration));
    }

    public void loadChild(SftpUser user, String username, String pass, String duration) {
        this.loadUser(new SftpUser(username, pass, true, duration, user.getHomeDir()));
    }

    public void loadUser(SftpUser user) {
        this.users.add(user);
        this.loadedUsers.add(user.getUsername());
        user.getHomeDir().toFile().mkdir();
        fileSystem.setUserHomeDir(user.getUsername(), user.getHomeDir());
    }

    public boolean start() {
        this.server.setUserAuthFactories(userAuthFactories);
        try {
            this.server.start();
            return true;
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }

}
