
import java.io.*;
import java.util.*;

import com.gc.android.market.api.MarketSession.Callback;
import com.gc.android.market.api.MarketSession;
import com.gc.android.market.api.model.Market.App;
import com.gc.android.market.api.model.Market.AppsResponse;
import com.gc.android.market.api.model.Market.AppsRequest;
import com.gc.android.market.api.model.Market.CommentsRequest;
import com.gc.android.market.api.model.Market.GetImageRequest;
import com.gc.android.market.api.model.Market.GetImageResponse;
import com.gc.android.market.api.model.Market.ResponseContext;
import com.gc.android.market.api.model.Market.GetImageRequest.AppImageUsage;

class test {

    /**
     * @param args
     */
    public static void main(String[] args) {
        try {
            if(args.length < 3) {
                System.out.println("Parameters :\n" +
                        "email password deviceid");
                return;
            }
            String login = args[0];
            String password = args[1];
            String deviceid = args[2];

            // Get a list of apps we want to check - i.e. those that
            // we have metadata files for...
            File dir = new File("../metadata");
            List<String> apps = new ArrayList<String>();
            String[] metafiles = dir.list();
            for (int i=0; i<metafiles.length; i++) {
                String metafile = metafiles[i];
                if(metafile.endsWith(".txt")) {
                    String pkg = metafile.substring(0,
                           metafile.length() - 4);
                    apps.add(pkg);
                }
            }
            System.out.println("Apps to check: " + apps.size());

            MarketSession session = new MarketSession();

            session.getContext().setAndroidId(deviceid);
            session.getContext().setDeviceAndSdkVersion("sapphire:7");
            System.out.println("Login...");
            session.login(login,password);
            System.out.println("Login done");

            MarketSession.Callback callback = new MarketSession.Callback() {

                @Override
                    public void onResult(ResponseContext context, Object oresp) {
                        try {
                            AppsResponse response = (AppsResponse)oresp;
                            if(response == null) {
                                System.out.println("No response");
                            }
                            if(response.getAppCount() != 1) {
                                System.out.println("Not in market, or multiple results");
                            } else {
                                App app = response.getAppList().get(0);
                                String filespec = "../metadata/" + app.getPackageName() + ".txt";
                                FileInputStream fi = new FileInputStream(filespec);
                                InputStreamReader isr = new InputStreamReader(fi, "UTF-8");
                                BufferedReader br = new BufferedReader(isr);
                                StringBuilder output = new StringBuilder();
                                boolean changed = false;
                                boolean vercodefound = false;
                                boolean versionfound = false;
                                String line, newline;
                                while (br.ready()) {
                                    line = br.readLine();
                                    if (line.startsWith("Market Version:")) {
                                        versionfound = true;
                                        newline="Market Version:" + app.getVersion();
                                        if (!newline.equals(line)) {
                                            changed = true;
                                            line = newline;
                                        }
                                    } else if (line.startsWith("Market Version Code:")) {
                                        vercodefound = true;
                                        newline="Market Version Code:" + app.getVersionCode();
                                        if (!newline.equals(line)) {
                                            changed = true;
                                            line = newline;
                                        }
                                    }
                                    output.append(line + "\n");
                                }
                                br.close();
                                isr.close();
                                fi.close();
                                if(!versionfound) {
                                    changed = true;
                                    output.append("Market Version:" + app.getVersion() + "\n");
                                }
                                if(!vercodefound) {
                                    changed = true;
                                    output.append("Market Version Code:" + app.getVersionCode() + "\n");
                                }

                                if (changed) { 
                                    System.out.println("..updating");
                                    FileOutputStream fo = new FileOutputStream(filespec);
                                    OutputStreamWriter osr = new OutputStreamWriter(fo, "UTF-8");
                                    BufferedWriter wi = new BufferedWriter(osr);
                                    wi.write(output.toString());
                                    wi.close();
                                    osr.close();
                                    fo.close();
                                }

                            }
                        } catch (Exception ex) {
                            System.out.println("...Exception");
                            ex.printStackTrace();
                        }
                    }

            };

            for(String pkg : apps) {
                System.out.println("Checking: " + pkg);
                AppsRequest appsRequest = AppsRequest.newBuilder()
                    .setQuery("pname:" + pkg)
                    .setStartIndex(0).setEntriesCount(10)
                    .setWithExtendedInfo(true)
                    .build();
                session.append(appsRequest, callback);
                session.flush();

                // Pause to avoid rate limit...
                Thread.sleep(5000);
            }

        } catch(Exception ex) {
            ex.printStackTrace();
        }
    }

}
