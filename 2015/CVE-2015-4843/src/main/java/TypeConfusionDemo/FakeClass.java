package TypeConfusionDemo;

public class FakeClass extends ParentClass {
  public static String classVar = "FakeClass";
  public int instanceVar;

  public FakeClass(int i) {
    this.instanceVar = i;
  }

  protected static int doWork() {
     System.out.println("Hello I am fake class");
  return 0;
  }

  public void foo(int i) {
    System.out.println("Called: FakeClass.foo(). I'm confused, and I'm not real.");
  }
}
  
