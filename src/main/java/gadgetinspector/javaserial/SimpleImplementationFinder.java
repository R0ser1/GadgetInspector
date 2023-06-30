package gadgetinspector.javaserial;

import gadgetinspector.ImplementationFinder;
import gadgetinspector.SerializableDecider;
import gadgetinspector.data.MethodReference;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class SimpleImplementationFinder implements ImplementationFinder  {

    private final SerializableDecider serializableDecider;
    private final Map<MethodReference.Handle, Set<MethodReference.Handle>> methodImplMap;

    public SimpleImplementationFinder(SerializableDecider serializableDecider, Map<MethodReference.Handle, Set<MethodReference.Handle>> methodImplMap) {
        this.serializableDecider = serializableDecider;
        this.methodImplMap = methodImplMap;
    }

    @Override
    public Set<MethodReference.Handle> getImplementations(MethodReference.Handle target) {
        Set<MethodReference.Handle> allImpls = new HashSet<>();

        // Assume that the target method is always available, even if not serializable; the target may just be a local
        // instance rather than something an attacker can control.
        allImpls.add(target);
        //methodImplMap:Key:类 方法 方法描述 value:子类 重写方法 方法描述 这一步就是获取所有重写的方法
        Set<MethodReference.Handle> subClassImpls = methodImplMap.get(target);
        if (subClassImpls != null) {//遍历判断是否可以序列化 可以就加入进去
            for (MethodReference.Handle subClassImpl : subClassImpls) {
                if (Boolean.TRUE.equals(serializableDecider.apply(subClassImpl.getClassReference()))) {
                    allImpls.add(subClassImpl);
                }
            }
        }

        return allImpls;
    }
}
