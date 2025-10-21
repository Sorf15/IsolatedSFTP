package com.sorf.IsolatedSFTP;

import com.sorf.IsolatedSFTP.subsystems.DeniedSftpSubsystem;
import com.sorf.IsolatedSFTP.util.*;
import io.github.cdimascio.dotenv.Dotenv;
import org.apache.sshd.server.auth.password.UserAuthPasswordFactory;

import java.io.*;
import java.lang.ref.SoftReference;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.CharacterIterator;
import java.text.StringCharacterIterator;
import java.time.Duration;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class Main {
    //TODO: encrypt logins, remake args, fix error codes
    private Main() {}

    public static SoftReference<SimpleServer> server = null;
    public static List<String> forbiddenWords = new ArrayList<>();
    public static final String forbiddenChars = "<>:\"/\\|?*";
    public static final Dotenv dotenv = Dotenv.load();
    static {
        forbiddenWords.add("CON");
        forbiddenWords.add("PRN");
        forbiddenWords.add("AUX");
        forbiddenWords.add("NUL");
        forbiddenWords.add("COM1");
        forbiddenWords.add("COM2");
        forbiddenWords.add("COM3");
        forbiddenWords.add("COM4");
        forbiddenWords.add("COM5");
        forbiddenWords.add("COM6");
        forbiddenWords.add("COM7");
        forbiddenWords.add("COM8");
        forbiddenWords.add("COM9");
        forbiddenWords.add("COM0");
        forbiddenWords.add("LPT1");
        forbiddenWords.add("LPT2");
        forbiddenWords.add("LPT3");
        forbiddenWords.add("LPT4");
        forbiddenWords.add("LPT5");
        forbiddenWords.add("LPT6");
        forbiddenWords.add("LPT7");
        forbiddenWords.add("LPT8");
        forbiddenWords.add("LPT9");
        forbiddenWords.add("LPT0");
    }

//-Dorg.slf4j.simpleLogger.defaultLogLevel=DEBUG
    public static void main(String[] args) {
        if (args.length != 4) {
            Logger.error("args.length must be 4, but given is %d", args.length);
            Logger.warn(Arrays.toString(args));
            Logger.warn("java -jar server.jar <path_to_the_work_folder> <port> <admin_username> <admin_pass>\n");
            Logger.warn("Continue with default settings? [y/n]");
            Scanner scanner = new Scanner(System.in);
            if (!scanner.nextLine().equals("y")) {
                Logger.warn("EXITING!");
                return;
            }
        } else {
            Reference.PATH = args[0];
            Reference.SERVER_PORT = Integer.parseInt(args[1]);
            Reference.ADMIN_USERNAME = args[2];
            Reference.ADMIN_PASS = args[3];
            Reference.PATH2 = Paths.get(Reference.PATH);
        }
        Logger.info("Hello World!");

        Logger.debug("Settings:");
        Logger.debug("Path = %s", Reference.PATH2.toAbsolutePath().toString());
        Logger.debug("ServerPort = %d", Reference.SERVER_PORT);
        Logger.debug("AdminUsername = %s", Reference.ADMIN_USERNAME);
        Logger.debug("AdminPass = %s", Reference.ADMIN_PASS);

        //init server
        SimpleServer server = new SimpleServer(Reference.SERVER_PORT, Paths.get(Reference.PATH));
        Main.server = new SoftReference<>(server);

        //get homeDir
        File homeDir = new File(Reference.PATH);
        if (!homeDir.exists() || !homeDir.isDirectory()) {
            Logger.error("0x06 - %s", homeDir.toString());
            throw new IllegalStateException();
        }

        //collect all users/directories
        File[] arr = homeDir.listFiles();
        if (arr == null) {
            Logger.error("0x07");
            throw new IllegalStateException();
        }
        List<String> files = Arrays.stream(arr).filter(File::isDirectory).map(File::getName).collect(Collectors.toList());

        //read saved users
        File users = new File(Reference.PATH, "users.dat");
        try {
            users.createNewFile();
        } catch (IOException e) {
            Logger.error("0x08");
            e.printStackTrace();
        }
        try (BufferedReader reader = new BufferedReader(new FileReader(users))) {
            reader.lines().forEach(s -> {
                String[] data = s.split("=");
                if (data.length != 3) {
                    Logger.error("0x01: %s", s);
                } else {
                    //load users
                    SftpUser user = new SftpUser(data[0], data[1], data[2]);
                    files.remove(user.getUsername());
                    server.loadUser(user);
                }
            });
        } catch (IOException e) {
            Logger.error("0x02!");
            e.printStackTrace();
        }

        //load unsaved users
        files.forEach(file -> server.loadUser(file, StringGenerator.generate(16)));

        //init server settings
        server.setPasswordAuthenticator((username, password, session) -> SftpUser.validateUser(username, password, server.getUsers()));
        server.setUserAuthFactories(new UserAuthPasswordFactory());
        server.setSubsystemFactories(new DeniedSftpSubsystem.Factory());

        server.start();

        //user duration and removal
        AsyncTask.getInstance().invoke(Main::updateUsers);

        Scanner sc = new Scanner(System.in);
        while (server.getServer().isOpen()) {
            try {
                String[] s = sc.nextLine().split(" ");
                processCommand(s, sc);
            } catch (Exception e) {
                Logger.error("GOT UNEXPECTED ERROR DURING COMMAND PROCESS!");
                e.printStackTrace();
            }
        }

        //saving users
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(users))) {
            server.getUsers().forEach(sftpUser -> {
                if (!sftpUser.isAdmin() && !sftpUser.getUsername().equals(Reference.ADMIN_USERNAME))
                try {
                    writer.write(sftpUser.getUsername());
                    writer.write("=");
                    writer.write(sftpUser.getPass());
                    writer.write("=");
                    if (sftpUser.isInf()) {
                        writer.write("inf");
                    } else {
                        String dur = sftpUser.getDuration().toString();
                        writer.write(dur.toLowerCase(), 2, dur.length() - 2);
                    }
                    writer.write('\n');
                } catch (IOException e) {
                    Logger.error("0x04!");
                    e.printStackTrace();
                }

            });
        } catch (IOException e) {
            Logger.error("0x03!");
            e.printStackTrace();
        }
        AsyncTask.getInstance().stop();
    }

    private static void processCommand(String[] s, Scanner sc) {
        switch (s[0]) {
            case "help":
            case "?":
                help();
                break;
            case "mem":
                Logger.info(humanReadableByteCountSI(getUsedMem()));
                break;
            case "gc":
                runGC();
                break;
            case "stop":
                stop();
                break;
            case "list":
                list(s);
                break;
            case "delAdm":
                delAdm(s);
                break;
            case "delUser":
                delUser(s, sc);
                break;
            case "setDur":
                setDur(s);
                break;
            case "setPass":
                setPass(s);
                break;
            case "generatePass":
                generatePass(s);
                break;
            case "suspend":
                suspend(s);
                break;
            case "append":
                append(s);
                break;
            case "freeSpace":
                freeSpace();
                break;
            case "totalUsedSpace":
                totalUsedSpace();
                break;
            case "usedSpace":
                usedSpace(s);
                break;
            case "addUser":
                addUser(s);
                break;
            case "addAdm":
                addAdm(s);
                break;
            default:
                Logger.info("Unknown command %s, use 'help' or '?' to list all commands", s[0]);
                break;
        }
    }

    private static void addAdm(String[] s) {
        if (s.length < 5) {
            Logger.warn("Given length of %d is not equal to 4\naddAdm <parent_ID> <username> <password> <duration>\n%s", s.length, Arrays.toString(s));
            return;
        }
        List<SftpUser> userList = server.get().getUsers();
        int i = 0;
        SftpUser user;
        try {
            //parsing user
            i = Integer.parseInt(s[1]);
            user = userList.get(i);
        } catch (IndexOutOfBoundsException e) {
            Logger.warn("Given ID %d not found!\naddAdm <parent_ID> <username> <password> <duration>\n%s", i, Arrays.toString(s));
            return;
        } catch (NumberFormatException e) {
            Logger.warn("Given argument is NaN: %s!\naddAdm <parent_ID> <username> <password> <duration>\n%s", s[1], Arrays.toString(s));
            return;
        }
        if (user.getUsername().equals(Reference.ADMIN_USERNAME)) {
            Logger.warn("Unsupported parent!");
            return;
        }

        if (isForbidden(s[2])) {
            Logger.warn("Unsupported username!");
            return;
        }

        if (s[2].isEmpty() || s[3].isEmpty()) {
            Logger.warn("Unsupported username/password! empty");
            return;
        }

        if (!containsOnlyLatinCharacters(s[2]) || !containsOnlyLatinCharacters(s[3])) {
            Logger.warn("Unsupported username/password! forbidden");
            return;
        }

        if (server.get().loadedUsers.contains(s[2])) {
            Logger.warn("Username '%s' is taken!", s[2]);
            return;
        }
        server.get().loadChild(user, s[2], s[3], s[4]);
        Logger.info("Created admin with username=%s pass=%s duration=%s path=%s", s[2], s[3], s[4], user.getHomeDir().getFileName());
    }

    private static void addUser(String[] s) {
        if (s.length < 4) {
            Logger.warn("Given length of %d is not equal to 5\naddUser <username> <password> <duration>\n%s", s.length, Arrays.toString(s));
            return;
        }

        if (s[1].equals(Reference.ADMIN_USERNAME) || s[1].equals("users.dat")) {
            Logger.warn("Username '%s' is taken!", s[1]);
            return;
        }
        if (isForbidden(s[1])) {
            Logger.warn("Unsupported username!");
            return;
        }

        if (s[1].isEmpty() || s[2].isEmpty()) {
            Logger.warn("Unsupported username/password!");
            return;
        }

        if (!containsOnlyLatinCharacters(s[1]) || !containsOnlyLatinCharacters(s[2])) {
            Logger.warn("Unsupported username/password!");
            return;
        }

        if (server.get().loadedUsers.contains(s[1])) {
            Logger.warn("Username '%s' is taken!", s[1]);
            return;
        }
        server.get().loadUser(s[1], s[2], s[3]);
        Logger.info("Created user with username=%s pass=%s duration=%s", s[1], s[2], s[3]);
    }

    private static void usedSpace(String[] s) {
        if (s.length < 2) {
            Logger.warn("Given length of %d is not equal to 2\nusedSpace <ID>\n%s", s.length, Arrays.toString(s));
            return;
        }
        List<SftpUser> userList = server.get().getUsers();
        int i = 0;
        try {
            //parsing user
            i = Integer.parseInt(s[1]);
            SftpUser user = userList.get(i);

            Logger.info("Used Space by %d - %s = %s", i, user.getUsername(), humanReadableByteCountSI(getDirectoryUsedSpace(user.getHomeDir().toFile())));
        } catch (IndexOutOfBoundsException e) {
            Logger.warn("Given ID %d not found!\nusedSpace <ID>\n%s", i, Arrays.toString(s));
        } catch (NumberFormatException e) {
            Logger.warn("Given argument is NaN: %s!\nusedSpace <ID>\n%s", s[1], Arrays.toString(s));
        }
    }

    private static void totalUsedSpace() {
        Logger.info("Total Used Space = %s", humanReadableByteCountSI(getDirectoryUsedSpace(Reference.PATH2.toFile())));
    }

    private static void freeSpace() {
        Logger.info("Free Space = %s", humanReadableByteCountSI(Reference.PATH2.toFile().getUsableSpace()));
    }


    //TODO: maybe DRY the code (fetching user) smh (all errors are hard-coded)
    private static void suspend(String[] s) {
        if (s.length < 2) {
            Logger.warn("Given length of %d is not equal to 2\nsuspend <ID>\n%s", s.length, Arrays.toString(s));
            return;
        }
        List<SftpUser> userList = server.get().getUsers();
        int i = 0;
        try {
            //parsing user
            i = Integer.parseInt(s[1]);
            SftpUser user = userList.get(i);

            user.setSuspended(true);
            closeUserSession(user, server.get());
            Logger.info("Suspended user with ID: %d - %s!", i, user.getUsername());
        } catch (IndexOutOfBoundsException e) {
            Logger.warn("Given ID %d not found!\nsuspend <ID>\n%s", i, Arrays.toString(s));
        } catch (NumberFormatException e) {
            Logger.warn("Given argument is NaN: %s!\nsuspend <ID>\n%s", s[1], Arrays.toString(s));
        }
    }

    private static void append(String[] s) {
        if (s.length < 2) {
            Logger.warn("Given length of %d is not equal to 2\nappend <ID>\n%s", s.length, Arrays.toString(s));
            return;
        }
        List<SftpUser> userList = server.get().getUsers();
        int i = 0;
        try {
            //parsing user
            i = Integer.parseInt(s[1]);
            SftpUser user = userList.get(i);

            user.setSuspended(false);
            Logger.info("Appended user with ID: %d - %s!", i, user.getUsername());
        } catch (IndexOutOfBoundsException e) {
            Logger.warn("Given ID %d not found!\nappend <ID>\n%s", i, Arrays.toString(s));
        } catch (NumberFormatException e) {
            Logger.warn("Given argument is NaN: %s!\nappend <ID>\n%s", s[1], Arrays.toString(s));
        }
    }

    private static void delUser(String[] s, Scanner sc) {
        //TODO: del all related admins
        if (s.length < 2) {
            Logger.warn("Given length of %d is not equal to 2\ndelUser <ID>\n%s", s.length, Arrays.toString(s));
            return;
        }
        List<SftpUser> userList = server.get().getUsers();
        int i = 0;
        try {
            //parsing user
            i = Integer.parseInt(s[1]);
            SftpUser user = userList.get(i);

            if (user.isAdmin()) {
                Logger.info("Given ID of %d - %s is an admin! Use 'delUser'", i, user.getUsername());
                return;
            }

            Logger.info("CONFIRM DELETING THE FOLLOWING USER: %d - %s [y/n]", i, user.toString());

            if (!sc.nextLine().equals("y")) {
                Logger.warn("DELETING CANCELED!");
                return;
            }
            Logger.warn("DELETING CONFIRMED!");

            //finding all relevant users
            removeAllUsersWithSameDir(user.getHomeDir(), server.get());
            server.get().loadedUsers.remove(user.getUsername());
            user.getHomeDir().toFile().delete();
            Logger.info("Removed user with ID: %d - %s!", i, user.getUsername());
        } catch (IndexOutOfBoundsException e) {
            Logger.warn("Given ID %d not found!\ndelUser <ID>\n%s", i, Arrays.toString(s));
        } catch (NumberFormatException e) {
            Logger.warn("Given argument is NaN: %s!\ndelUser <ID>\n%s", s[1], Arrays.toString(s));
        }
    }

    private static void generatePass(String[] s) {
        if (s.length < 3) {
            Logger.warn("Given length of %d is not equal to 3\ngeneratePass <ID> <length>\n%s", s.length, Arrays.toString(s));
            return;
        }
        List<SftpUser> userList = server.get().getUsers();
        int i = 0;
        try {
            i = Integer.parseInt(s[1]);
            int j = Integer.parseInt(s[2]);
            SftpUser user = userList.get(i);
            user.setPass(StringGenerator.generate(j));
            Logger.info("Set Password of %d - %s to %s", i, user.getUsername(), user.getPass());
        } catch (IndexOutOfBoundsException e) {
            Logger.warn("Given ID %d not found!\ngeneratePass <ID> <length>\n%s", i, Arrays.toString(s));
        } catch (NumberFormatException e) {
            Logger.warn("Given argument is NaN!\ngeneratePass <ID> <length>\n%s", Arrays.toString(s));
        }
    }

    private static void delAdm(String[] s) {
        if (s.length < 2) {
            Logger.warn("Given length of %d is not equal to 2\ndelAdm <ID>\n%s", s.length, Arrays.toString(s));
            return;
        }
        List<SftpUser> userList = server.get().getUsers();
        int i = 0;
        try {
            //parsing user
            i = Integer.parseInt(s[1]);
            SftpUser user = userList.get(i);

            if (!user.isAdmin() || user.getUsername().equals(Reference.ADMIN_USERNAME)) {
                Logger.info("Given ID of %d - %s is not an admin! Use 'delUser'", i, user.getUsername());
                return;
            }
            //finding session with this name
            closeUserSession(user, server.get());

            server.get().getUsers().remove(i);
            server.get().loadedUsers.remove(user.getUsername());
            Logger.info("Removed admin-user with ID: %d - %s!", i, user.getUsername());
        } catch (IndexOutOfBoundsException e) {
            Logger.warn("Given ID %d not found!\ndelAdm <ID>\n%s", i, Arrays.toString(s));
        } catch (NumberFormatException e) {
            Logger.warn("Given argument is NaN: %s!\ndelAdm <ID>\n%s", s[1], Arrays.toString(s));
        }
    }

    private static void setPass(String[] s) {
        if (s.length < 3) {
            Logger.warn("Given length of %d is not equal to 3\nsetPass <ID> <pass>\n%s", s.length, Arrays.toString(s));
            return;
        }
        List<SftpUser> userList = server.get().getUsers();
        int i = 0;
        try {
            i = Integer.parseInt(s[1]);
            SftpUser user = userList.get(i);
            user.setPass(s[2]);
            Logger.info("Set Password of %d - %s to %s", i, user.getUsername(), s[2]);
        } catch (IndexOutOfBoundsException e) {
            Logger.warn("Given ID %d not found!\nsetPass <ID> <pass>\n%s", i, Arrays.toString(s));
        } catch (NumberFormatException e) {
            Logger.warn("Given argument is NaN: %s!\nsetPass <ID> <pass>\n%s", s[1], Arrays.toString(s));
        }
    }

    private static void setDur(String[] s) {
        if (s.length < 3) {
            Logger.warn("Given length of %d is not equal to 3\nsetDur <ID> <duration/inf>\n%s", s.length, Arrays.toString(s));
            return;
        }
        List<SftpUser> userList = server.get().getUsers();
        int i = 0;
        try {
            i = Integer.parseInt(s[1]);
            SftpUser user = userList.get(i);
            if (s[2].equals("inf")) {
                user.setInf(true);
                user.setDuration(Duration.ZERO);
                Logger.info("Set Duration of %d - %s to %s", i, user.getUsername(), "infinite");
            } else {
                user.setDuration(TimeUtil.parseDuration(s[2]));
                Logger.info("Set Duration of %d - %s to %s", i, user.getUsername(), user.getDuration().toString());
            }
        } catch (IndexOutOfBoundsException e) {
            Logger.warn("Given ID %d not found!\nsetDur <ID> <duration/inf>\n%s", i, Arrays.toString(s));
        } catch (NumberFormatException e) {
            Logger.warn("Given argument is NaN: %s!\nsetDur <ID> <duration/inf>\n%s", s[1], Arrays.toString(s));
        }

    }

    private static void list(String[] s) {
        List<SftpUser> userList = server.get().getUsers();
        for (int i = 0; i < userList.size(); i++) {
            System.out.print(i);
            System.out.print(" = ");
            System.out.println(userList.get(i));
        }
    }

    private static long getUsedMem() {
        return Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
    }

    private static void runGC() {
        long l = getUsedMem();
        Logger.info("Running GarbageCollector!");
        Runtime.getRuntime().gc();
        Logger.info("GarbageCollector has finished!");
        Logger.info("Freed " + humanReadableByteCountSI(l - getUsedMem()));
    }

    private static void stop() {
        try {
            Objects.requireNonNull(server.get()).getServer().stop();
        } catch (Exception e) {
            Logger.error("Couldn't stop the server!");
            e.printStackTrace();
            Runtime.getRuntime().exit(-1);
        }
    }

    private static void help() {
        Logger.info("help - shows this");
        Logger.info("gc - runs garbage collector");
        Logger.info("mem - shows amount of memory used in bytes");
        Logger.info("stop - stops the server");
        Logger.info("list - lists all available users");
        Logger.info("setDur <ID> <duration/inf> - sets the time after which the user will be deleted (examples of duration: 1w4d15h55m2s");
        Logger.info("setPass <ID> <pass> - sets new pass for user");
        Logger.info("generatePass <ID> <length> - generates new password for corresponding user");
        Logger.info("delAdm <ID> - deletes user with admin privileges (not the catalogue or default user)");
        Logger.info("delUser <ID> - deletes user and corresponding admin acc");
        Logger.info("suspend <ID> - suspends user from connecting");
        Logger.info("append <ID> - appends user for connecting");
        Logger.info("freeSpace - shows available space");
        Logger.info("usedSpace <ID> - shows used space by the specific user");
        Logger.info("totalUsedSpace - shows total used Space");
        Logger.info("addUser <username> <password> <duration> - adds new user");
        Logger.info("addAdm <parent_ID> <username> <password> <duration> - adds Adm user based on some other user's folder");
    }

    public static String humanReadableByteCountSI(long bytes) {
        if (-1000 < bytes && bytes < 1000) {
            return bytes + " B";
        }
        CharacterIterator ci = new StringCharacterIterator("kMGTPE");
        while (bytes <= -999_950 || bytes >= 999_950) {
            bytes /= 1000;
            ci.next();
        }
        return String.format("%.1f %cB", bytes / 1000.0, ci.current());
    }

    public static long getDirectoryUsedSpace(File file) {
        long res = 0L;
        if (file.isDirectory()) {
            for (String s : file.list()) {
                res += getDirectoryUsedSpace(new File(file, s));
            }
        } else if (file.exists()) {
            res += file.length();
        }
        return res;
    }

    public static boolean containsAnyChars(String original, String compared) {
        for (char c : compared.toCharArray()) {
            if (original.contains(String.valueOf(c))) {
                return true;
            }
        }
        return false;
    }

    public static boolean isForbidden(String s) {
        for (String s1 : forbiddenWords) {
            if (s.equals(s1)) {
                return true;
            }
        }
        return containsAnyChars(s, forbiddenChars);
    }

    public static boolean containsOnlyLatinCharacters(String str) {
        // Regular expression to match only Latin characters
        String regex = "^[\\p{IsLatin}]+$";
        return Pattern.matches(regex, str);
    }

    private static void updateUsers() {
        SimpleServer server = Main.server.get();
        List<SftpUser> userList = server.getUsers();
        while (server.getServer().isOpen()) {
            userList.forEach(sftpUser -> {
                if (sftpUser.update()) {
                    sftpUser.setSuspended(true);
                    closeUserSession(sftpUser, server);
                }
            });
        }
    }

    private static void removeAllUsersWithSameDir(Path homeDir, SimpleServer server) {
        server.getUsers().stream().filter(user -> user.getHomeDir().getFileName().equals(homeDir.getFileName()))
                .collect(Collectors.toList())
                .forEach(user -> {
                    server.getUsers().remove(user);
                    server.loadedUsers.remove(user.getUsername());
                });
    }

    private static void closeUserSession(SftpUser user, SimpleServer server) {
        server.getServer().getActiveSessions().stream().filter(abstractSession -> //filter only sessions with provided username
                        abstractSession.getUsername().equals(user.getUsername()))
                .collect(Collectors.toList()).forEach(session ->{ //for each found
                    try {
                        session.close();
                    } catch (IOException e) {
                        Logger.error("0x07");
                        e.printStackTrace();
                    }
                });
    }



//    public static void inf_loop(boolean loop) {
//        boolean b = false;
//        while (loop) {
//            b = !b;
//        }
//    }
//
//    private static void ssh_server() {
//        SshServer sshd = SshServer.setUpDefaultServer();
//        sshd.setPort(2222); // Set your desired port
//
//        // Set host key provider (generates a new key every time)
//        sshd.setKeyPairProvider(new SimpleGeneratorHostKeyProvider(Paths.get("hostkey.ser")));
//
//        // Set password authenticator
//        PasswordAuthenticator passwordAuthenticator = (username, password, session) -> username.equals("test") && password.equals("1234");
//        sshd.setPasswordAuthenticator(passwordAuthenticator);
//
//        sshd.setFileSystemFactory(new VirtualFileSystemFactory(Paths.get("D:\\inteliij\\mincraft-protocol\\src\\main\\java\\com\\sorf")));
//
//        // Set user auth service
//        List<UserAuthFactory> list = new ArrayList<>();
//        list.add(new UserAuthPasswordFactory());
//        sshd.setUserAuthFactories(list);
//
////        List<UserAuthFactory> userAuthFactories = new ArrayList<>();
////        userAuthFactories.add(UserAuthNoneFactory.INSTANCE);
////        sshd.setUserAuthFactories(userAuthFactories);
//
//        sshd.setCommandFactory(new ProcessShellCommandFactory());
//
//        sshd.setSubsystemFactories(Collections.singletonList(new SftpSubsystemFactory()));
//        // Start the server
//
//        Thread thread = new Thread(() -> {
//            try {
//                sshd.start();
//            } catch (IOException e) {
//                e.printStackTrace();
//            }
//        });
//        thread.start();
//        boolean b = false;
//        while (!sshd.isClosed()){
//            b = !b;
//        }
//    }
//
//    private static void ssh_client() {
//        try {
//            JSch jsch = new JSch();
//
//            // Replace these values with your server information
//            String username = "test";
//            String password = "1234";
//            String host = "localhost";
//            int port = 2222;
//
//            // Create a session
//            Session session = jsch.getSession(username, host, port);
//            session.setPassword(password);
//
//            // Avoid checking the host key
//            java.util.Properties config = new java.util.Properties();
//            config.put("StrictHostKeyChecking", "no");
//            session.setConfig(config);
//
//            // Connect to the server
//            session.connect();
//
//            // Create an SFTP channel
//            ChannelSftp channel = (ChannelSftp) session.openChannel("sftp");
//            channel.connect();
//
//            channel.ls("./*");
//
//            // Use the channel to perform SFTP operations
//            // For example, you can upload/download files, list directories, etc.
//
//            // Disconnect the SFTP channel and session when done
//            channel.disconnect();
//            session.disconnect();
//        } catch (JSchException | SftpException e) {
//            e.printStackTrace();
//        }
//    }

}
