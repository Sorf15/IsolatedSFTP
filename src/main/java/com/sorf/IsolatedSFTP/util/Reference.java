package com.sorf.IsolatedSFTP.util;

import com.sorf.IsolatedSFTP.Main;

import java.nio.file.Path;
import java.nio.file.Paths;

public class Reference {
    public static String PATH = System.getProperty("user.dir");
    public static int SERVER_PORT = 22222;
    public static String ADMIN_USERNAME = Main.dotenv.get("ADMIN_USERNAME");
    public static String ADMIN_PASS = Main.dotenv.get("ADMIN_PASS");
    public static Path PATH2 = Paths.get(PATH);
}
