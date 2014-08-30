import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.Signature;
import java.security.cert.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

public class getsig {

    public static void main(String[] args) {

        String apkPath = null;
        boolean full = false;

        if(args.length == 1) {
            apkPath = args[0];
        } else if (args.length == 2) {
            if(!args[0].equals("-f")) {
                System.out.println("Only -f is supported");
                System.exit(1);
            }
            apkPath = args[1];
            full = true;
        } else {
            System.out.println("Specify the APK file to get the signature from!");
            System.exit(1);
        }

        try {

            JarFile apk = new JarFile(apkPath);
            java.security.cert.Certificate[] certs = null;

            Enumeration entries = apk.entries();
            while (entries.hasMoreElements()) {
                JarEntry je = (JarEntry) entries.nextElement();
                if (!je.isDirectory() && !je.getName().startsWith("META-INF/")) {
                    // Just need to read the stream (discarding the data) to get
                    // it to process the certificate...
                    byte[] b = new byte[4096];
                    InputStream is = apk.getInputStream(je);
                    while (is.read(b, 0, b.length) != -1);
                    is.close();
                    certs = je.getCertificates();
                    if(certs != null)
                        break;
                }
            }
            apk.close();

            if (certs == null) {
                System.out.println("Not signed");
                System.exit(1);
            }
            if (certs.length != 1) {
                System.out.println("One signature expected");
                System.exit(1);
            }

            // Get the signature in the same form that is returned by
            // android.content.pm.Signature.toCharsString() (but in the
            // form of a byte array so we can pass it to the MD5 function)...
            byte[] sig = certs[0].getEncoded();
            byte[] csig = new byte[sig.length * 2];
            for (int j=0; j<sig.length; j++) {
                byte v = sig[j];
                int d = (v>>4)&0xf;
                csig[j*2] = (byte)(d >= 10 ? ('a' + d - 10) : ('0' + d));
                d = v&0xf;
                csig[j*2+1] = (byte)(d >= 10 ? ('a' + d - 10) : ('0' + d));
            }

            String result;
            if(full) {
                result = new String(csig);
            } else {
                // Get the MD5 sum...
                MessageDigest md;
                md = MessageDigest.getInstance("MD5");
                byte[] md5sum = new byte[32];
                md.update(csig);
                md5sum = md.digest();
                BigInteger bigInt = new BigInteger(1, md5sum);
                String md5hash = bigInt.toString(16);
                while (md5hash.length() < 32)
                    md5hash = "0" + md5hash;
                result = md5hash;
            }

            System.out.println("Result:" + result);
            System.exit(0);

        } catch (Exception e) {
            System.out.println("Exception:" + e);
            System.exit(1);
        }
    }

}


