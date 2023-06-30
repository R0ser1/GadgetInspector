package gadgetinspector.javaserial;

import gadgetinspector.SerializableDecider;
import gadgetinspector.SourceDiscovery;
import gadgetinspector.data.*;
import org.objectweb.asm.Type;

import java.util.Map;
import java.util.Set;

public class SimpleSourceDiscovery extends SourceDiscovery {

    @Override
    public void discover(Map<ClassReference.Handle, ClassReference> classMap,
                         Map<MethodReference.Handle, MethodReference> methodMap,
                         InheritanceMap inheritanceMap,
                         Map<MethodReference.Handle, Set<GraphCall>> graphCallMap) {

        final SerializableDecider serializableDecider = new SimpleSerializableDecider(inheritanceMap);

        for (MethodReference.Handle method : methodMap.keySet()) {
            //遍历所有方法 然后通过决策器的apply方法去匹配 该类是否可以序列化
            if (Boolean.TRUE.equals(serializableDecider.apply(method.getClassReference()))) {
                //可以的话判断方法是否是如下 也就是一些常见 序列化回自动调用的方法
                if (method.getName().equals("finalize") && method.getDesc().equals("()V")) {
                    addDiscoveredSource(new Source(method, 0));
                }
            }
        }

        // 如果一个类实现了 readObject 方法，那么传递给该方法的 ObjectInputStream 对象被认为是 tainted 的（即受污染的）
        for (MethodReference.Handle method : methodMap.keySet()) {
            if (Boolean.TRUE.equals(serializableDecider.apply(method.getClassReference()))) {
                if (method.getName().equals("readObject") && method.getDesc().equals("(Ljava/io/ObjectInputStream;)V")) {
                    addDiscoveredSource(new Source(method, 1));
                }
            }
        }

        // 使用代理，任何继承 Serializable 和 InvocationHandler 的对象都被认为是 tainted（即受污染的）。
        for (ClassReference.Handle clazz : classMap.keySet()) {
            if (Boolean.TRUE.equals(serializableDecider.apply(clazz))
                    && inheritanceMap.isSubclassOf(clazz, new ClassReference.Handle("java/lang/reflect/InvocationHandler"))) {
                MethodReference.Handle method = new MethodReference.Handle(
                        clazz, "invoke", "(Ljava/lang/Object;Ljava/lang/reflect/Method;[Ljava/lang/Object;)Ljava/lang/Object;");

                addDiscoveredSource(new Source(method, 0));
            }
        }

        //
        // 将对象放入 HashMap 的技巧，可以访问 hashCode() 或 equals() 方法作为入口点。
        for (MethodReference.Handle method : methodMap.keySet()) {
            if (Boolean.TRUE.equals(serializableDecider.apply(method.getClassReference()))) {
                if (method.getName().equals("hashCode") && method.getDesc().equals("()I")) {
                    addDiscoveredSource(new Source(method, 0));
                }
                if (method.getName().equals("equals") && method.getDesc().equals("(Ljava/lang/Object;)Z")) {
                    addDiscoveredSource(new Source(method, 0));
                    addDiscoveredSource(new Source(method, 1));
                }
            }
        }

        // 使用比较器代理，我们可以跳转到任何 Groovy 闭包（Closure）的 call() 或 doCall() 方法中，并且所有的参数都会被标记为 tainted。
        //
        // https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/Groovy1.java
        for (MethodReference.Handle method : methodMap.keySet()) {
            if (Boolean.TRUE.equals(serializableDecider.apply(method.getClassReference()))
                    && inheritanceMap.isSubclassOf(method.getClassReference(), new ClassReference.Handle("groovy/lang/Closure"))
                    && (method.getName().equals("call") || method.getName().equals("doCall"))) {

                addDiscoveredSource(new Source(method, 0));
                Type[] methodArgs = Type.getArgumentTypes(method.getDesc());
                for (int i = 0; i < methodArgs.length; i++) {
                    addDiscoveredSource(new Source(method, i + 1));
                }
            }
        }
    }

    public static void main(String[] args) throws Exception {
        SourceDiscovery sourceDiscovery = new SimpleSourceDiscovery();
        sourceDiscovery.discover();
        sourceDiscovery.save();
    }
}
