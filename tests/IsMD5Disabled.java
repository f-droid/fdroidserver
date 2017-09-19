
import java.security.Security;
import java.util.Locale;

public class IsMD5Disabled {
    public static void main(String[] args) throws Exception {
        String daString = Security.getProperty("jdk.jar.disabledAlgorithms");
        String[] algorithms = daString.trim().split(",");
        boolean isMD5Disabled = true;
        for (String alg : algorithms) {
            if (alg.trim().toLowerCase(Locale.US).startsWith("md5")) {
                isMD5Disabled = false;
            }
        }
        if (isMD5Disabled) {
            System.out.println("MD5 in jdk.jar.disabledAlgorithms: " + daString);
        } else {
            System.out.println("MD5 allowed for JAR signatures: " + daString);
            System.exit(1);
        }
    }
}
