# Description
Deatils for the vulnerability is disucssed on [confluence](https://thehut.atlassian.net/wiki/spaces/SOT/pages/3701669956/CVE-2015-4843+-+Phrack+paper). 
This repo has been picked up after a few years on being dead, not looked at the `DisabledSecurityManager` code.
## TypeConfusionDemo
## OverflowDemo
This is a demo that shows we can overflow into before the `dst` array. This demo works on `aarch64` and `morello`, although the overflow is only stopped on the WIP branch where the bounds are tightly contrained. Which is pretty cool as it shows that using cheri capabilities alone does not offer the sufficient portection for managed runtimes, and we need to constrain our heap.  
## TypeConfusionDemo
This demo should that by copying a `FakeClass oop` into an array of `RealClass` by using the overflow, we cam type confused it and make it execute the function of `FakeClass`. This demo only works on `aarch64`, as on `morello` an `oop` would not be a `MemoryAddress`, and we can't use `IntBuffer` exploit anymore. Which is an interesting side benefit to our port.
# How to run
Both the overflow and type confusion can be run from the jar witjh arg:
* `overflow`: runs the `OverflowDemo`
* `confusion`: runs the `TypeConfusionDemo`

an example is:
`./build/bsd-aarch64-template-aarch64-release/jdk/bin/java -Xmx8G -Xms8G -XX:+UnlockExperimentalVMOptions -XX:+UseEpsilonGC -jar /home/slatere/phrack/target/TestOverflow-1.0-SNAPSHOT-jar-with-dependencies.jar confusion`

the jar is generated onto the remote by using the [build-phrack.yml](https://github.com/Soteria-Research/generic-playbooks/blob/master/ansible/benchmarks/build-phrack.yml).