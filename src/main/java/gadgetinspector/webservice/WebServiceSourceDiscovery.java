package gadgetinspector.webservice;


import gadgetinspector.SourceDiscovery;
import gadgetinspector.data.*;

import java.util.Map;
import java.util.Set;

public class WebServiceSourceDiscovery extends SourceDiscovery {

    @Override
    public void discover(Map<ClassReference.Handle, ClassReference> classMap, Map<MethodReference.Handle, MethodReference> methodMap, InheritanceMap inheritanceMap, Map<MethodReference.Handle, Set<GraphCall>> graphCallMap) {
        final WebServiceSerializableDecider springDecider = new WebServiceSerializableDecider(methodMap);

        for (MethodReference.Handle method : methodMap.keySet()) {
            MethodReference methodValue = methodMap.get(method);

            Set<GraphCall> graphCalls = graphCallMap.get(method);
            if (graphCalls == null) {
                continue;
            }
            if (springDecider.apply(method.getClassReference())) {
                for (GraphCall graphCall : graphCalls){
                    if (methodValue.getMethodAnnotationDesc().contains("Lorg/springframework/web/bind/annotation/RequestMapping")
                            || methodValue.getMethodAnnotationDesc().contains("Lorg/springframework/web/bind/annotation/GetMapping")
                            || methodValue.getMethodAnnotationDesc().contains("Lorg/springframework/web/bind/annotation/PostMapping")
                            || methodValue.getParameterAnnotationDesc().contains("Lorg/springframework/web/bind/annotation/RequestParam")
                            || methodValue.getMethodAnnotationDesc().contains("Lorg/springframework/web/bind/annotation/PutMapping")
                            || methodValue.getMethodAnnotationDesc().contains("Lorg/springframework/web/bind/annotation/PatchMapping")
                            || methodValue.getParameterAnnotationDesc().contains("Lorg/springframework/web/bind/annotation/DeleteMapping")
                            ||methodValue.getParameterAnnotationDesc().contains("Lorg/springframework/stereotype/Controller")
                            ||methodValue.getParameterAnnotationDesc().contains("Lorg/springframework/web/bind/annotation/RestController")
                            ||methodValue.getParameterAnnotationDesc().contains("Lorg/springframework/web/bind/annotation/ResponseBody")
                    ) {
                        if (graphCall.getCallerArgIndex()!=0){
                            addDiscoveredSource(new Source(method, graphCall.getCallerArgIndex()));
                        }
                    }
                    if ((graphCall.getTargetMethod().getName().equals("getQueryString")
                            || graphCall.getTargetMethod().getName().equals("getParameter")
                            || graphCall.getTargetMethod().getName().equals("getParameterNames")
                            || graphCall.getTargetMethod().getName().equals("getParameterValues")
                            || graphCall.getTargetMethod().getName().equals("getParameterMap")
                            || graphCall.getTargetMethod().getName().equals("getRemoteHost")
                            || graphCall.getTargetMethod().getName().equals("getLocalName")
                            || graphCall.getTargetMethod().getName().equals("getServerName"))
                            && (inheritanceMap.isSubclassOf(graphCall.getTargetMethod().getClassReference(),
                            new ClassReference.Handle("javax/servlet/ServletRequest"))
                            ||graphCall.getTargetMethod().getClassReference().equals("javax/servlet/ServletRequest"))
                    ){
                        if (graphCall.getCallerArgIndex()!=0){
                            addDiscoveredSource(new Source(method, graphCall.getCallerArgIndex()));
                        }
                    }
                    if ((graphCall.getTargetMethod().getName().equals("getComment")
                            || graphCall.getTargetMethod().getName().equals("getDomain")
                            || graphCall.getTargetMethod().getName().equals("getName")
                            || graphCall.getTargetMethod().getName().equals("getPath")
                            || graphCall.getTargetMethod().getName().equals("getValue"))
                            && (inheritanceMap.isSubclassOf(graphCall.getTargetMethod().getClassReference(),
                            new ClassReference.Handle("javax/servlet/http/Cookie"))
                            ||graphCall.getTargetMethod().getClassReference().equals("javax/servlet/http/Cookie"))
                    ){
                        if (graphCall.getCallerArgIndex()!=0){
                            addDiscoveredSource(new Source(method, graphCall.getCallerArgIndex()));
                        }
                    }
                    if ((graphCall.getTargetMethod().getName().startsWith("get"))
                            && (inheritanceMap.isSubclassOf(graphCall.getTargetMethod().getClassReference(),
                            new ClassReference.Handle("javax/servlet/http/HttpServletRequestWrapper"))
                            ||graphCall.getTargetMethod().getClassReference().equals("javax/servlet/http/HttpServletRequestWrapper"))
                    ){
                        if (graphCall.getCallerArgIndex()!=0){
                            addDiscoveredSource(new Source(method, graphCall.getCallerArgIndex()));
                        }
                    }
                    //todo 只认为requests是污点
                    if(!method.getName().contains("<init>")
                            && (method.getDesc().contains("Ljavax/servlet/http/HttpServletRequest")
                            || method.getDesc().contains("Ljavax/servlet/ServletRequest"))){
                        if (graphCall.getCallerArgIndex()!=0){
                            String[] argTypes = graphCall.getCallerMethod().getDesc().substring(1, graphCall.getCallerMethod().getDesc().indexOf(')')).split(";");
                            String targetArgType = "Ljavax/servlet/http/HttpServletRequest";
                            int targetIndex = -1;
                            for (int i = 0; i < argTypes.length; i++) {
                                if (argTypes[i].equals(targetArgType)) {
                                    targetIndex = i;
                                    break;
                                }
                            }
                            if (targetIndex+1==graphCall.getCallerArgIndex()){
                                addDiscoveredSource(new Source(method, graphCall.getCallerArgIndex()));
                            }
                        }
                    }
                }
            }
        }
    }
}
