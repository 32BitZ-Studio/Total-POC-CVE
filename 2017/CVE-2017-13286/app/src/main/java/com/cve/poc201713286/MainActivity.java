package com.cve.poc201713286;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Log.e("yes","MainActivity被执行了");
        setContentView(R.layout.activity_main);
        Intent serviceIntent = new Intent(this, AuthenticatorService.class);
        startService(serviceIntent);
    }
}