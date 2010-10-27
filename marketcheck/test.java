
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
            if(args.length < 2) {
                System.out.println("Parameters :\n" +
                        "email password");
                return;
            }
            String login = args[0];
            String password = args[1];

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
            System.out.println("Login...");
            session.login(login,password);
            System.out.println("Login done");

            MarketSession.Callback callback = new MarketSession.Callback() {

                @Override
                    public void onResult(ResponseContext contex, Object oresp) {
                        AppsResponse response = (AppsResponse)oresp;
                        if(response.getAppCount() != 1) {
                            System.out.println("Not in market, or multiple results");
                        } else {
                            App app = response.getAppList().get(0);
                            System.out.println("  Package:" + app.getPackageName());
                            System.out.println("  Version Code:" + app.getVersionCode());
                            System.out.println("  Version:" + app.getVersion());
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
