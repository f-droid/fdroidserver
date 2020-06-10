
import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.Writer;
import java.io.InputStreamReader;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.IntBuffer;
import java.util.Random;

// apt-get install libcommons-lang3-java
//import org.apache.commons.lang3.RandomStringUtils;

public class RandomPackageNames {

    private static Writer validWriter;
    private static Writer invalidWriter;

    private static final String[] py = {
        "python3", "-c",
        "import sys,re\n"
        + "m = re.search(r'''"
        //        + "^(?:[a-z_]+(?:\\d*[a-zA-Z_]*)*)(?:\\.[a-z_]+(?:\\d*[a-zA-Z_]*)*)*$"
        + "^[a-z_]+(?:\\d*[a-zA-Z_]*)(?:\\.[a-z_]+(?:\\d*[a-zA-Z_]*)*)*$"
        + "''', sys.stdin.read())\n"
        + "if m is not None:\n"
        + "  with open('/tmp/foo', 'w') as fp:\n"
        + "    fp.write(m.group() + '\\n')\n"
        + "sys.exit(m is None)"
    };
    
    public static boolean checkAgainstPython(String packageName)
        throws IOException, InterruptedException {

        ProcessBuilder pb = new ProcessBuilder(py);
        Process process = pb.start();
        OutputStream output = process.getOutputStream();
        output.write(packageName.getBytes());
        output.write("\n".getBytes());
        output.flush();
        output.close();

        int exitVal = process.waitFor();
        return exitVal == 0;
    }

    private static boolean isValidJavaIdentifier(String packageName) {
        if (packageName.length() == 0 || !Character.isJavaIdentifierStart(packageName.charAt(0))) {
            //System.out.println("invalid first char: '" + packageName + "'");
            return false;
        }
        for (int codePoint : packageName.codePoints().toArray()) {
            if (codePoint != 46 && !Character.isJavaIdentifierPart(codePoint)) {
                //System.out.println("invalid char: '"
                //                   + new StringBuilder().appendCodePoint(codePoint).toString() + "' "
                //                   + codePoint);
                return false;
            }
        }
        return true;
    }

    private static void write(String packageName) throws IOException {
        if (isValidJavaIdentifier(packageName)) {
            validWriter.write(packageName);
            validWriter.write("\n");
        } else {
            invalidWriter.write(packageName);
            invalidWriter.write("\n");
        }
    }

    private static void compare(String packageName)
        throws IOException, InterruptedException {
        boolean python = checkAgainstPython(packageName);
        boolean java = isValidJavaIdentifier(packageName);
        if (python && !java) {
            System.out.println("MISMATCH: '" + packageName + "' "
                               + (python ? "py:✔" : "py:☹") + " "
                               + (java ? "ja:✔" : "ja:☹") + " ");
        }
    }
    
    public static void main (String[] args)
        throws IOException, InterruptedException, UnsupportedEncodingException {
        int[] data;
        byte[] bytes;
        ByteBuffer byteBuffer;
        Random random = new Random();

        validWriter = new OutputStreamWriter(new FileOutputStream("valid.txt"), "UTF-8");
        invalidWriter = new OutputStreamWriter(new FileOutputStream("invalid.txt"), "UTF-8");
        
        //System.out.print(".");

        char[] validFirstLetters = new char[27];
        validFirstLetters[0] = 95; // _
        for (int i = 1; i < 27; i++) {
            validFirstLetters[i] = (char) (i + 96);
        }

        char[] validLetters = new char[64];
        int j = 0;
        for (char c = 32; c < 123; c++) {
            if ((c == 46) || (c > 47 && c < 58) || (c > 64 && c < 91) || (c > 96)) {
                validLetters[j] = c;
                j++;
            }
        }

        for (File f : new File("/home/hans/code/fdroid/fdroiddata/metadata").listFiles()) {
            String name = f.getName();
            if (name.endsWith(".yml")) {
                compare(name.substring(0, name.length() - 4));
            }
        }
        compare("SpeedoMeterApp.main");
        compare("uk.co.turtle-player");
        compare("oVPb");
        compare(" _LS");
        compare("r.vq");
        compare("r.vQ");
        compare("ra.vQ");
        compare("s.vQ");
        compare("r.tQ");
        compare("r.vR");
        compare("any.any");
        compare("org.fdroid.fdroid");
        compare("me.unfollowers.droid");
        compare("me_.unfollowers.droid");
        compare("me._unfollowers.droid");
        compare("me.unfo11llowers.droid");
        compare("me11.unfollowers.droid");
        compare("m11e.unfollowers.droid");
        compare("1me.unfollowers.droid");
        compare("me.unfollowers23.droid");
        compare("me.unfollowers.droid23d");
        compare("me.unfollowers_.droid");
        compare("me.unfollowers._droid");
        compare("me.unfollowers_._droid");
        compare("me.unfollowers.droid_");
        compare("me.unfollowers.droid32");
        compare("me.unfollowers.droid/");
        compare("me:.unfollowers.droid");
        compare(":me.unfollowers.droid");
        compare("me.unfollowers.dro;id");
        compare("me.unfollowe^rs.droid");
        compare("me.unfollowers.droid.");
        compare("me.unfollowers..droid");
        compare("me.unfollowers.droid._");
        compare("me.unfollowers.11212");
        compare("me.1.unfollowers.11212");
        compare("me..unfollowers.11212");
        compare("abc");
        compare("abc.");
        compare(".abc");

        for (int i = 0; i < 300000; i++) {
            String packageName;

            int count = random.nextInt(10) + 1;
            byte valid = (byte) random.ints(97, 122).limit(1).toArray()[0];

            // only valid
            data = random.ints(46, 122)
                .limit(count)
                .filter(c -> (c == 46) || (c > 47 && c < 58) || (c > 64 && c < 91) || (c > 96))
                .toArray();
            byteBuffer = ByteBuffer.allocate(data.length);
            for (int value : data) {
                byteBuffer.put((byte)value);
            }
            if (data.length > 0) {
                bytes = byteBuffer.array();
                bytes[0] = valid;
                packageName = new String(byteBuffer.array(), "UTF-8");
                //System.out.println(packageName + ": " + isValidJavaIdentifier(packageName));
                compare(packageName);
                write(packageName);
            }

            // full US-ASCII
            data = random.ints(32, 126).limit(count).toArray();
            byteBuffer = ByteBuffer.allocate(data.length);
            for (int value : data) {
                byteBuffer.put((byte)value);
            }
            bytes = byteBuffer.array();
            packageName = new String(bytes, "UTF-8");
            //System.out.println(packageName + ": " + isValidJavaIdentifier(packageName));
            compare(packageName);
            write(packageName);

            // full US-ASCII with valid first letter
            data = random.ints(32, 127).limit(count).toArray();
            byteBuffer = ByteBuffer.allocate(data.length * 4);
            byteBuffer.asIntBuffer().put(data);
            bytes = byteBuffer.array();
            bytes[0] = valid;
            packageName = new String(bytes, "UTF-8");
            //System.out.println(packageName + ": " + isValidJavaIdentifier(packageName));
            compare(packageName);
            write(packageName);

            // full unicode
            data = random.ints(32, 0xFFFD).limit(count).toArray();
            byteBuffer = ByteBuffer.allocate(data.length * 4);
            byteBuffer.asIntBuffer().put(data);
            packageName = new String(byteBuffer.array(), "UTF-32");
            //System.out.println(packageName + ": " + isValidJavaIdentifier(packageName));
            compare(packageName);
            write(packageName);

            // full unicode with valid first letter
            data = random.ints(32, 0xFFFD).limit(count).toArray();
            byteBuffer = ByteBuffer.allocate(data.length * 4);
            byteBuffer.asIntBuffer().put(data);
            bytes = byteBuffer.array();
            bytes[0] = 0;
            bytes[1] = 0;
            bytes[2] = 0;
            bytes[3] = 120;
            packageName = new String(bytes, "UTF-32");
            //System.out.println(packageName + ": " + isValidJavaIdentifier(packageName));
            compare(packageName);
            write(packageName);
        }

        validWriter.close();
        invalidWriter.close();
    }
}
