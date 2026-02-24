package TypeConfusionDemo;

public class RealClass extends ParentClass {
  public static String classVar = "RealClass";
  public int instanceVar;

  public RealClass(int i) {
  	this.instanceVar = i;
  }

  protected static int doWork() {
   System.out.println("RealClass doWork()");
   System.out.println("classVar = " + classVar);
  return 1;
  }
  
  public void foo(int i) {
    System.out.println("Called: RealClass.foo()");
  }

}
