/*
 * Piwigo for Android
 * Copyright (C) 2016-2017 Piwigo Team http://piwigo.org
 * Copyright (C) 2018      Raphael Mack http://www.raphael-mack.de
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package org.piwigo;

import android.app.Activity;
import android.app.Application;
import android.app.Service;
import android.content.Context;
import androidx.databinding.DataBindingUtil;
import androidx.multidex.MultiDex;

import org.acra.ACRA;
import org.acra.ReportField;
import org.acra.annotation.AcraCore;
import org.acra.annotation.AcraDialog;
import org.acra.annotation.AcraMailSender;
import org.acra.data.StringFormat;
import org.piwigo.helper.DialogHelper;
import org.piwigo.helper.NetworkHelper;
import org.piwigo.helper.NotificationHelper;
import org.piwigo.internal.di.component.ApplicationComponent;
import org.piwigo.internal.di.component.BindingComponent;
import org.piwigo.internal.di.component.DaggerApplicationComponent;
import org.piwigo.internal.di.component.DaggerBindingComponent;
import org.piwigo.internal.di.module.ApplicationModule;

import javax.inject.Inject;

import dagger.android.AndroidInjector;
import dagger.android.DispatchingAndroidInjector;
import dagger.android.HasActivityInjector;
import dagger.android.HasServiceInjector;

@AcraCore(reportContent = { ReportField.APP_VERSION_CODE,
        ReportField.APP_VERSION_NAME,
        ReportField.USER_COMMENT,
        ReportField.SHARED_PREFERENCES,
        ReportField.ANDROID_VERSION,
        ReportField.CUSTOM_DATA,
        ReportField.STACK_TRACE,
        ReportField.BUILD,
        ReportField.BUILD_CONFIG,
        ReportField.CRASH_CONFIGURATION,
        ReportField.DISPLAY
    },
    alsoReportToAndroidFramework = true,
    reportFormat = StringFormat.KEY_VALUE_LIST
)
@AcraMailSender(mailTo = "android@piwigo.org")
@AcraDialog(resCommentPrompt = R.string.crash_dialog_comment_prompt,
        resText = R.string.crash_dialog_text)
public class PiwigoApplication extends Application implements HasActivityInjector, HasServiceInjector {

    @Inject DispatchingAndroidInjector<Activity> dispatchingAndroidInjector;
    @Inject DispatchingAndroidInjector<Service> dispatchingAndroidServiceInjector;

    private ApplicationComponent applicationComponent;

    @Override public void onCreate() {
        super.onCreate();

        new NetworkHelper();
        new NotificationHelper(getApplicationContext());
        new DialogHelper()
;        initializeDependencyInjection();
    }

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        MultiDex.install(base);
        ACRA.init(this);
    }

    @Override public AndroidInjector<Activity> activityInjector() {
        return dispatchingAndroidInjector;
    }

    private void initializeDependencyInjection() {
        applicationComponent = DaggerApplicationComponent.builder()
                .applicationModule(new ApplicationModule(this))
                .build();
        applicationComponent.inject(this);

        BindingComponent bindingComponent = DaggerBindingComponent.builder()
                .applicationComponent(applicationComponent)
                .build();
        DataBindingUtil.setDefaultComponent(bindingComponent);
    }

    /**
     * Returns an {@link AndroidInjector} of {@link Service}s.
     */
    @Override
    public AndroidInjector<Service> serviceInjector() {
        return dispatchingAndroidServiceInjector;
    }
}