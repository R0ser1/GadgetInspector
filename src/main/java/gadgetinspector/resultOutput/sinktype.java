package gadgetinspector.resultOutput;

import gadgetinspector.ConfigHelper;
import gadgetinspector.GadgetChainDiscovery;
import gadgetinspector.data.ClassReference;
import gadgetinspector.data.InheritanceMap;
import gadgetinspector.data.MethodReference;

import java.util.*;
import java.util.stream.Collectors;

public class sinktype {
    private static final String RCE = "Remote Code/Command Execute.";
    private static final String XXE = "XXE Injection.";
    private static final String SSRF = "Server Request Forgery.";
    private static final String SQL = "SQL Injection.";
    private static final String File = "File operation.";
    private static final String Other = "Other.";
    private static final String Redirect = "Open Redirect.";
    private static final String JNDI = "JNDI Injection";
    private static final String JDBC = "JDBC Injection";

    public String type_Category(MethodReference.Handle method, int argIndex, InheritanceMap inheritanceMap) {
        return Sink(method, argIndex, inheritanceMap);
    }

    public String Sink(MethodReference.Handle method, int argIndex,
                       InheritanceMap inheritanceMap) {

        return isSink(method,argIndex,inheritanceMap);
    }
    private String isSink(MethodReference.Handle method, int argIndex,
                           InheritanceMap inheritanceMap) {
        String classname = method.getClassReference().getName();
        String subclassname = classname.substring(classname.lastIndexOf('/') + 1);
        String methodNamen = method.getName();

        GadgetChainDiscovery gadgetChainDiscovery = new GadgetChainDiscovery();
        if ((ConfigHelper.sinks.isEmpty() || ConfigHelper.sinks.stream().map(String::toUpperCase).collect(Collectors.toSet()).contains("JNDI")) && gadgetChainDiscovery.JNDISink(method, inheritanceMap)) {
            return RCE+JNDI;
        }
        if ((ConfigHelper.sinks.isEmpty() || ConfigHelper.sinks.stream().map(String::toUpperCase).collect(Collectors.toSet()).contains("XXE")) && gadgetChainDiscovery.XXESink(method, inheritanceMap)) {
            return XXE+subclassname+methodNamen;
        }
        if ((ConfigHelper.sinks.isEmpty() || ConfigHelper.sinks.stream().map(String::toUpperCase).collect(Collectors.toSet()).contains("EXEC")) && gadgetChainDiscovery.EXECSink(method, argIndex, inheritanceMap)) {
            return RCE+subclassname+methodNamen;
        }
        if ((ConfigHelper.sinks.isEmpty() || ConfigHelper.sinks.stream().map(String::toUpperCase).collect(Collectors.toSet()).contains("FILEIO")) && gadgetChainDiscovery.FileIOSink(method, argIndex)) {
            return File+subclassname+methodNamen;
        }
        if ((ConfigHelper.sinks.isEmpty() || ConfigHelper.sinks.stream().map(String::toUpperCase).collect(Collectors.toSet()).contains("REFLECT")) && gadgetChainDiscovery.ReflectSink(method, argIndex, inheritanceMap)) {
            return RCE+subclassname+methodNamen;
        }
        if ((ConfigHelper.sinks.isEmpty() || ConfigHelper.sinks.stream().map(String::toUpperCase).collect(Collectors.toSet()).contains("JDBC")) && gadgetChainDiscovery.JDBCSink(method, argIndex, inheritanceMap)) {
            return RCE+JDBC;
        }
        if ((ConfigHelper.sinks.isEmpty() || ConfigHelper.sinks.stream().map(String::toUpperCase).collect(Collectors.toSet()).contains("EL")) && gadgetChainDiscovery.ELSink(method, argIndex, inheritanceMap)) {
            return RCE+subclassname+methodNamen;
        }
        if ((ConfigHelper.sinks.isEmpty() || ConfigHelper.sinks.stream().map(String::toUpperCase).collect(Collectors.toSet()).contains("SQL")) && gadgetChainDiscovery.isSQLInjectSink(method, argIndex, inheritanceMap)) {
            return SQL+subclassname+methodNamen;
        }
        if ((ConfigHelper.sinks.isEmpty() || ConfigHelper.sinks.stream().map(String::toUpperCase).collect(Collectors.toSet()).contains("SSRF")) && gadgetChainDiscovery.SSRFSink(method)) {
            return SSRF+subclassname+methodNamen;
        }
        if ((ConfigHelper.sinks.isEmpty() || ConfigHelper.sinks.stream().map(String::toUpperCase).collect(Collectors.toSet()).contains("SSTI")) && gadgetChainDiscovery.SSTISink(method)) {
            return RCE+subclassname+methodNamen;
        }
        if ((ConfigHelper.sinks.isEmpty() || ConfigHelper.sinks.stream().map(String::toUpperCase).collect(Collectors.toSet()).contains("DESERIALIZE")) && gadgetChainDiscovery.deserializeSink(method)) {
            return RCE+subclassname+methodNamen;
        }
        if ((ConfigHelper.sinks.isEmpty() || ConfigHelper.sinks.stream().map(String::toUpperCase).collect(Collectors.toSet()).contains("XPATH")) && gadgetChainDiscovery.XpathSink(method)) {
            return Other+subclassname+methodNamen;
        }
        if ((ConfigHelper.sinks.isEmpty() || ConfigHelper.sinks.stream().map(String::toUpperCase).collect(Collectors.toSet()).contains("EXPRESSION")) && gadgetChainDiscovery.ExpressionSink(method)) {
            return RCE+subclassname+methodNamen;
        }

        if ((ConfigHelper.sinks.isEmpty() || ConfigHelper.sinks.stream().map(String::toUpperCase).collect(Collectors.toSet()).contains("REDIRECT")) && gadgetChainDiscovery.RedirectSink(method, argIndex)) {
            return Redirect+subclassname+methodNamen;
        }
        return null;
    }

}