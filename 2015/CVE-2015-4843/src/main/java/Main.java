import java.lang.reflect.Field;

import TypeConfusionDemo.TypeConfusionDemo;
import src.main.java.TypeConfusionDemo.OverflowDemo;
import sun.misc.Unsafe;

class Main {
    private static Unsafe unsafe;
    public static void main(String []args){
        try {
            switch(args[0]) {
                case "overflow":
                    OverflowDemo overflow = new OverflowDemo();
                    overflow.testOverflow();
                    break;
                case "confusion":
                    TypeConfusionDemo demo = new TypeConfusionDemo();
                    demo.demo();
                    break;
                default:
                    System.out.println("Arg must be either: overflow or confusion");
                }
        } catch(Exception e) {
            System.out.println(e);
        }
    }
    

}