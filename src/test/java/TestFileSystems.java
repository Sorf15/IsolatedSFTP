import java.io.File;
import java.nio.file.Paths;

public class TestFileSystems {
    private static final String PATH = "D:\\inteliij\\mincraft-protocol\\src\\main\\java\\com\\sorf";

    public static void main(String[] args) {

        String s = System.getProperty("user.dir");
        System.out.println(new File(s).isDirectory());
    }
}
