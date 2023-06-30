package gadgetinspector.javaserial;

import gadgetinspector.SerializableDecider;
import gadgetinspector.data.ClassReference;
import gadgetinspector.data.InheritanceMap;

import java.util.HashMap;
import java.util.Map;

public class SimpleSerializableDecider implements SerializableDecider {
    private final Map<ClassReference.Handle, Boolean> cache = new HashMap<>();
    private final InheritanceMap inheritanceMap;

    public SimpleSerializableDecider(InheritanceMap inheritanceMap) {
        this.inheritanceMap = inheritanceMap;
    }

    @Override
    public Boolean apply(ClassReference.Handle handle) {
        Boolean cached = cache.get(handle);
        if (cached != null) {
            return cached;
        }
        //判断是否继承了Serializable以及是否是黑名单的类
        Boolean result = applyNoCache(handle);
        //设置一个缓存 避免重复
        cache.put(handle, result);
//        //测试都可以反序列化
//        return true;
        return result;
    }

    private Boolean applyNoCache(ClassReference.Handle handle) {
        //是否是黑名单里面的类
        if (isBlacklistedClass(handle)) {
            return false;
        }
        //判断该类的父类是否继承了Serializable
        if (inheritanceMap.isSubclassOf(handle, new ClassReference.Handle("java/io/Serializable"))) {
            return true;
        }

        return false;
    }

    private static boolean isBlacklistedClass(ClassReference.Handle clazz) {
        if (clazz.getName().startsWith("com/google/common")) {
            return true;
        }
//        if (clazz.getName().startsWith("org/apache/commons/collections4/functors/InvokerTransformer")){
//            return true;
//        }

        // Serialization of these classes has been disabled since clojure 1.9.0
        // https://github.com/clojure/clojure/commit/271674c9b484d798484d134a5ac40a6df15d3ac3
        if (clazz.getName().equals("clojure/core/proxy$clojure/lang/APersistentMap$ff19274a")
                || clazz.getName().equals("clojure/inspector/proxy$javax/swing/table/AbstractTableModel$ff19274a")) {
            return true;
        }

        return false;
    }
}
