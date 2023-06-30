package gadgetinspector.config;

import gadgetinspector.ImplementationFinder;
import gadgetinspector.SerializableDecider;
import gadgetinspector.SourceDiscovery;
import gadgetinspector.data.ClassReference;
import gadgetinspector.data.InheritanceMap;
import gadgetinspector.data.MethodReference;
import gadgetinspector.webservice.WebServiceImplementationFinder;
import gadgetinspector.webservice.WebServiceSerializableDecider;
import gadgetinspector.webservice.WebServiceSourceDiscovery;

import java.util.Map;
import java.util.Set;

public class WebServiceDeserializationConfig implements GIConfig {
    @Override
    public String getName() {
        return "webservice";
    }

    @Override
    public SerializableDecider getSerializableDecider(Map<MethodReference.Handle, MethodReference> methodMap, InheritanceMap inheritanceMap) {
        return new WebServiceSerializableDecider(methodMap);
    }

    @Override
    public ImplementationFinder getImplementationFinder(Map<MethodReference.Handle, MethodReference> methodMap,
                                                        Map<MethodReference.Handle, Set<MethodReference.Handle>> methodImplMap,
                                                        InheritanceMap inheritanceMap, Map<ClassReference.Handle, Set<MethodReference.Handle>> methodsByClass) {
        return new WebServiceImplementationFinder(getSerializableDecider(methodMap, inheritanceMap), methodImplMap, methodsByClass);
    }

    @Override
    public SourceDiscovery getSourceDiscovery() {
        return new WebServiceSourceDiscovery();
    }

}
