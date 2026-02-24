package TypeConfusionDemo;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.IntBuffer;
import sun.misc.Unsafe;

public class DemoHelper {
    public static String format_hex(int dec) {
        return String.format("%02x", dec);
    }

    public static int[] init_array(int array_size, int hex_fill) {
        int[] new_array = new int[array_size];
        for (int i = 0; i < array_size; i++) {
          new_array[i] = hex_fill;
        }
        return new_array;
      }

    public static IntBuffer init_int_buffer(int ib_size, int hex_fill) {
        ByteBuffer bb = ByteBuffer.allocateDirect(ib_size);
        IntBuffer ib = bb.asIntBuffer();
        for (int i = 0; i < ib.limit(); i++) {
          ib.put(i, hex_fill);
        }
        return ib;
    } 

    public static Unsafe getUnsafe() throws NoSuchFieldException, IllegalAccessException {
      Field field = Unsafe.class.getDeclaredField("theUnsafe");
      field.setAccessible(true);
      return (Unsafe) field.get(null);
  }
}
