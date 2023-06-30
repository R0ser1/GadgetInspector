package gadgetinspector.webservice;

import gadgetinspector.SerializableDecider;
import gadgetinspector.data.ClassReference;
import gadgetinspector.data.MethodReference;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class WebServiceSerializableDecider implements SerializableDecider {
    //类是否通过决策的缓存集合
    private final Map<ClassReference.Handle, Boolean> cache = new HashMap<>();

    //类名-方法集合
    private final Map<ClassReference.Handle, Set<MethodReference.Handle>> methodsByClassMap;

    public WebServiceSerializableDecider(Map<MethodReference.Handle, MethodReference> methodMap){
        this.methodsByClassMap  = new HashMap<>();
        for (MethodReference.Handle method : methodMap.keySet()) {
            Set<MethodReference.Handle> classMethods = methodsByClassMap.get(method.getClassReference());
            if (classMethods == null) {
                classMethods = new HashSet<>();
                methodsByClassMap.put(method.getClassReference(), classMethods);
            }
            classMethods.add(method);
        }
    }

    @Override
    public Boolean apply(ClassReference.Handle handle) {
        if (isbalck(handle)) {
            return false;
        }
        return Boolean.TRUE;
    }
    //过滤jar的一些source
    private boolean isbalck(ClassReference.Handle clazz) {
        if (clazz.getName().startsWith("org/thymeleaf")
                ||clazz.getName().startsWith("com/alibaba/fastjson")
                ||clazz.getName().startsWith("ch/qos/logback")
                ||clazz.getName().startsWith("org/springframework")
                ||clazz.getName().startsWith("org/apache/catalina")
                ||clazz.getName().startsWith("javax/servlet")
                ||clazz.getName().startsWith("org/apache/tomcat")
        ){
            return true;
        }
        return false;
    }
}
