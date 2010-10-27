
import java.io.FileOutputStream;

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
                        "email password package");
                return;
            }


            String login = args[0];
            String password = args[1];
            String query = args.length > 2 ? args[2] : "Test";

            MarketSession session = new MarketSession();
            System.out.println("Login...");
            session.login(login,password);
            System.out.println("Login done");

            AppsRequest appsRequest = AppsRequest.newBuilder()
                .setQuery(query)
                .setStartIndex(0).setEntriesCount(10)
                .setWithExtendedInfo(true)
                .build();

            MarketSession.Callback callback = new MarketSession.Callback() {

                @Override
                    public void onResult(ResponseContext contex, Object oresp) {
                        AppsResponse response = (AppsResponse)oresp;
                        if(response.getAppCount() != 1) {
                            System.out.println("Not in market, or multiple results");
                        } else {
                            App app = response.getAppList().get(0);
                            System.out.println("Version Code:" + app.getVersionCode());
                            System.out.println("Version:" + app.getVersion());
                        }
                    }

            };
            session.append(appsRequest, callback);
            session.flush();
        } catch(Exception ex) {
            ex.printStackTrace();
        }
    }

}
