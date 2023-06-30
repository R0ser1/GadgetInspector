package gadgetinspector.data;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class InheritanceDeriver {
    private static final Logger LOGGER = LoggerFactory.getLogger(InheritanceDeriver.class);

    public static InheritanceMap derive(Map<ClassReference.Handle, ClassReference> classMap) {
        LOGGER.debug("Calculating inheritance for " + (classMap.size()) + " classes...");
        Map<ClassReference.Handle, Set<ClassReference.Handle>> implicitInheritance = new HashMap<>();
        for (ClassReference classReference : classMap.values()) {
            if (implicitInheritance.containsKey(classReference.getHandle())) {
                throw new IllegalStateException("Already derived implicit classes for " + classReference.getName());
            }
            Set<ClassReference.Handle> allParents = new HashSet<>();
            /*
            获取该class的superclass 以及 Interfaces
            通过递归得到所有的父类  通过allParents 也是就是hashset储存起来
            */
            getAllParents(classReference, classMap, allParents);
            // 将class和class 的allparents put到这个hashmap中
            implicitInheritance.put(classReference.getHandle(), allParents);
        }
        // InheritanceMap是里面设置了subClassMap  将父类为key 子类给添加进去
        return new InheritanceMap(implicitInheritance);
    }

    private static void getAllParents(ClassReference classReference, Map<ClassReference.Handle, ClassReference> classMap, Set<ClassReference.Handle> allParents) {
        Set<ClassReference.Handle> parents = new HashSet<>();
        //添加父类
        if (classReference.getSuperClass() != null) {
            parents.add(new ClassReference.Handle(classReference.getSuperClass()));
        }
        //添加接口
        for (String iface : classReference.getInterfaces()) {
            parents.add(new ClassReference.Handle(iface));
        }

        for (ClassReference.Handle immediateParent : parents) {
            ClassReference parentClassReference = classMap.get(immediateParent);
            if (parentClassReference == null) {
                LOGGER.debug("No class id for " + immediateParent.getName());
                continue;
            }
            allParents.add(parentClassReference.getHandle());
            getAllParents(parentClassReference, classMap, allParents);
        }
    }

    public static Map<MethodReference.Handle, Set<MethodReference.Handle>> getAllMethodImplementations(
            InheritanceMap inheritanceMap, Map<MethodReference.Handle, MethodReference> methodMap) {
        //遍历整合，得到每个类的所有方法实现，形成 类->实现的方法集 的映射
        Map<ClassReference.Handle, Set<MethodReference.Handle>> methodsByClass = new HashMap<>();
        for (MethodReference.Handle method : methodMap.keySet()) {
            ClassReference.Handle classReference = method.getClassReference();
            if (!methodsByClass.containsKey(classReference)) {
                Set<MethodReference.Handle> methods = new HashSet<>();
                methods.add(method);
                methodsByClass.put(classReference, methods);
            } else {
                methodsByClass.get(classReference).add(method);
            }
        }


        Map<ClassReference.Handle, Set<ClassReference.Handle>> subClassMap = new HashMap<>();
        //遍历继承关系数据，形成 父类->子孙类集 的映射  // ps:上面已经通过InheritanceMap包装 里面已经实现过这一步了 且加入了进去也就是subClassMap
        //多余的步骤
//        for (Map.Entry<ClassReference.Handle, Set<ClassReference.Handle>> entry : inheritanceMap.entrySet()) {
//            for (ClassReference.Handle parent : entry.getValue()) {
//                if (!subClassMap.containsKey(parent)) {
//                    Set<ClassReference.Handle> subClasses = new HashSet<>();
//                    subClasses.add(entry.getKey());
//                    subClassMap.put(parent, subClasses);
//                } else {
//                    subClassMap.get(parent).add(entry.getKey());
//                }
//            }
//        }
        //todo 后续更改使用
        subClassMap=inheritanceMap.getSubClassMap();

        //对重写方法处理。得到方法 -> 子类重写的方法
        Map<MethodReference.Handle, Set<MethodReference.Handle>> methodImplMap = new HashMap<>();
        for (MethodReference method : methodMap.values()) {
            // 静态方法不会重写 跳过
            if (method.isStatic()) {
                continue;
            }

            Set<MethodReference.Handle> overridingMethods = new HashSet<>();
            //得到该方法的子类
            Set<ClassReference.Handle> subClasses = subClassMap.get(method.getClassReference());
            if (subClasses != null) {
                for (ClassReference.Handle subClass : subClasses) {
                    // 遍历子类 以及从methodsByClass对象中获取指定子类的所有方法
                    Set<MethodReference.Handle> subClassMethods = methodsByClass.get(subClass);
                    if (subClassMethods != null) {
                        for (MethodReference.Handle subClassMethod : subClassMethods) {
                            //当前方法是否与指定的子类方法匹配 描述符和名称相同 找到的重载方法的句柄都存储在了overridingMethods集合
                            if (subClassMethod.getName().equals(method.getName()) && subClassMethod.getDesc().equals(method.getDesc())) {
                                overridingMethods.add(subClassMethod);
                            }
                        }
                    }
                }
            }

            if (overridingMethods.size() > 0) {
                methodImplMap.put(method.getHandle(), overridingMethods);
            }
        }
        //返回 方法名为key 以及  all重写该方法的方法名为Value
        return methodImplMap;
    }

    //测试添加
    public static Map<ClassReference.Handle, Set<MethodReference.Handle>> getMethodsByClass(
            Map<MethodReference.Handle, MethodReference> methodMap) {
        Map<ClassReference.Handle, Set<MethodReference.Handle>> methodsByClass = new HashMap<>();
        for (MethodReference.Handle method : methodMap.keySet()) {
            ClassReference.Handle classReference = method.getClassReference();
            if (!methodsByClass.containsKey(classReference)) {
                Set<MethodReference.Handle> methods = new HashSet<>();
                methods.add(method);
                methodsByClass.put(classReference, methods);
            } else {
                methodsByClass.get(classReference).add(method);
            }
        }
        return methodsByClass;
    }
}
