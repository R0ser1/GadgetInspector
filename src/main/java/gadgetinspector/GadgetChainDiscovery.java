    package gadgetinspector;

import gadgetinspector.config.GIConfig;
import gadgetinspector.config.JavaDeserializationConfig;
import gadgetinspector.data.*;
import gadgetinspector.resultOutput.ResultInfo;
import gadgetinspector.resultOutput.ResultOutput;
import gadgetinspector.resultOutput.sinktype;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.stream.Collectors;

public class GadgetChainDiscovery {

    private static final Logger LOGGER = LoggerFactory.getLogger(GadgetChainDiscovery.class);

    private GIConfig config;
    public GadgetChainDiscovery() {
    }
    public GadgetChainDiscovery(GIConfig config) {
        this.config = config;
    }

    public void discover(List<Path> pathList) throws Exception {

        //把methods.dat 加载传递  其中key 为classReference name desc ||  value为前面说的加一个是否为静态方法
        Map<MethodReference.Handle, MethodReference> methodMap = DataLoader.loadMethods();
        // 继承类 一个class 的父类和接口 然后使用InheritanceMap包装  其中包含inheritanceMap subClassMap 而后者是父类与子类的映射 key为父类  value是子类
        InheritanceMap inheritanceMap = InheritanceMap.load();
        //得到方法 -> 子类重写的方法的集合
        Map<MethodReference.Handle, Set<MethodReference.Handle>> methodImplMap = InheritanceDeriver.getAllMethodImplementations(
                inheritanceMap, methodMap);
        //测试 获取该类下所有的方法
        Map<ClassReference.Handle, Set<MethodReference.Handle>> methodsByClass = InheritanceDeriver.getMethodsByClass(methodMap);
        //通过ImplementationFinder对象将inheritanceMap通过serializableDecider封装 和methodImplMap储存起来
        final ImplementationFinder implementationFinder = config.getImplementationFinder(
                methodMap, methodImplMap, inheritanceMap,methodsByClass);

        //存储到methodimpl 格式为key:类 方法 方法描述 value：子类 重写方法 方法描述
        try (Writer writer = Files.newBufferedWriter(Paths.get("methodimpl.dat"))) {
            for (Map.Entry<MethodReference.Handle, Set<MethodReference.Handle>> entry : methodImplMap.entrySet()) {
                writer.write(entry.getKey().getClassReference().getName());
                writer.write("\t");
                writer.write(entry.getKey().getName());
                writer.write("\t");
                writer.write(entry.getKey().getDesc());
                writer.write("\n");
                for (MethodReference.Handle method : entry.getValue()) {
                    writer.write("\t");
                    writer.write(method.getClassReference().getName());
                    writer.write("\t");
                    writer.write(method.getName());
                    writer.write("\t");
                    writer.write(method.getDesc());
                    writer.write("\n");
                }
            }
        }
        //graphCallMap将方法调用按照调用者进行分组以便后续快速地查找任意一个方法的所有调用信息
        // 每个调用者方法引用句柄作为Key，对应多个被调用者对象的集合为Value
        Map<MethodReference.Handle, Set<GraphCall>> graphCallMap = new HashMap<>();
        for (GraphCall graphCall : DataLoader.loadData(Paths.get("callgraph.dat"), new GraphCall.Factory())) {
            MethodReference.Handle caller = graphCall.getCallerMethod();
            if (!graphCallMap.containsKey(caller)) {
                Set<GraphCall> graphCalls = new HashSet<>();
                graphCalls.add(graphCall);
                graphCallMap.put(caller, graphCalls);
            } else {
                graphCallMap.get(caller).add(graphCall);
            }
        }
        //exploredMethods用于存储已经探索过的方法链引用  methodsToExplore存储形成的方法链 也可以说是待探索的方法链
        Set<GadgetChainLink> exploredMethods = new HashSet<>();
        LinkedList<GadgetChain> methodsToExplore = new LinkedList<>();
        for (Source source : DataLoader.loadData(Paths.get("sources.dat"), new Source.Factory())) {
            GadgetChainLink srcLink = new GadgetChainLink(source.getSourceMethod(), source.getTaintedArgIndex());
            if (exploredMethods.contains(srcLink)) {
                continue;
            }
            methodsToExplore.add(new GadgetChain(Arrays.asList(srcLink)));
            exploredMethods.add(srcLink);
        }

        long iteration = 0;
        Set<GadgetChain> discoveredGadgets = new HashSet<>();

        // 定义newlink的访问次数 //测试
        Map<GadgetChainLink, Integer> exploredMethodNumber = new HashMap<>();


        while (methodsToExplore.size() > 0) {
            if ((iteration % 10000) == 0) {
                LOGGER.info("Iteration " + iteration + ", Search space: " + methodsToExplore.size());
            }
            iteration += 1;
            //移除第一个方法链 赋值给chain
            GadgetChain chain = methodsToExplore.pop();
            //取这条链最后一个节点
            GadgetChainLink lastLink = chain.links.get(chain.links.size()-1);
            //限定链长度
            if (chain.links.size() >= ConfigHelper.maxChainLength) {
                continue;
            }

            //获取当前节点方法 所有的 子方法与当前节点方法参数传递关系
            Set<GraphCall> methodCalls = graphCallMap.get(lastLink.method);
            if (methodCalls != null) {
                for (GraphCall graphCall : methodCalls) {
                    if (graphCall.getCallerArgIndex() != lastLink.taintedArgIndex && ConfigHelper.taintTrack) {
                        //判断当前的节点方法的污染参数与当前子方法受父方法参数影响的Index不一致则跳过 污点分析
                        continue;
                    }
                    //获取所有的实现类 也就是此方法所有此方法的重写方法 且是可以序列化的
                    // todo bug? 没有添加自身？
                    Set<MethodReference.Handle> allImpls = implementationFinder.getImplementations(graphCall.getTargetMethod());
                    // 添加目标 这里是是为了不使用rt.jar等进行污点分析
                    allImpls.add(graphCall.getTargetMethod());

                    //todo 这里是反向父类去查找方法 先判断自身是否存在此方法 不存在 才去父类寻找
                    if (methodsByClass.get(graphCall.getTargetMethod().getClassReference())!=null
                            &&!methodsByClass.get(graphCall.getTargetMethod().getClassReference()).contains(graphCall.getTargetMethod())){

                        Set<ClassReference.Handle> parents = inheritanceMap.getSuperClasses(graphCall.getTargetMethod().getClassReference());
                        if (parents != null){
                        for (ClassReference.Handle parent : parents) {
                            Set<MethodReference.Handle> methods = methodsByClass.get(parent);
                            if (methods != null){
                            for (MethodReference.Handle method : methods) {
                                if (method.getName().equals(graphCall.getTargetMethod().getName()) && method.getDesc().equals(graphCall.getTargetMethod().getDesc())) {
                                    allImpls.add(method);
                                }
                            }
                        }
                    }
                }
            }
                    //测试结束
                    for (MethodReference.Handle methodImpl : allImpls) {
                        GadgetChainLink newLink = new GadgetChainLink(methodImpl, graphCall.getTargetArgIndex());
//
//                        if (exploredMethods.contains(newLink)) {
//                            continue; //这里就是如果包含了此方法 说明已经访问过 就是为例避免出现环 但是丢掉了其他链
//                        }
                    //todo 这里改动一下  增加访问次数 //测试开始
                        if (exploredMethods.contains(newLink)) {
                            if (exploredMethodNumber.containsKey(newLink)){
                                //添加最大的访问次数
                                if(exploredMethodNumber.get(newLink) > ConfigHelper.maxRepeatBranchesTimes){
                                    continue;
                                }
                                exploredMethodNumber.put(newLink, exploredMethodNumber.get(newLink)+1);
                            }
                            else {
                                exploredMethodNumber.put(newLink, 1);
                            }
                        }
                        //测试结束

                        //将现有的链chain 和新newLink连接起来，形成一个新的链条。
                        GadgetChain newChain = new GadgetChain(chain, newLink);
                        if (isSink(methodImpl, graphCall.getTargetArgIndex(), inheritanceMap)) {
                            discoveredGadgets.add(newChain);
                        } else {
                            methodsToExplore.add(newChain);
                            exploredMethods.add(newLink);
                        }
                    }
                }
            }
        }


        // todo 解决路径爆炸，即中间路径重复率过高的问题
        if (ConfigHelper.similarLevel> 0){
            TreeSet<GadgetChain> treeSimilar = new TreeSet<>(new Comparator<GadgetChain>() {
                @Override
                public int compare(GadgetChain o1, GadgetChain o2) {
                    int compareResult = o1.links.size() - o2.links.size();
                    if (compareResult == 0){
                        return -1;
                    }
                    return compareResult;

                }
            });


            if (ConfigHelper.useJDKchain){
                for (GadgetChain chain : discoveredGadgets) {
                    if (chain.links.size() <= ConfigHelper.similarLevel){
                        continue;
                    }
                    treeSimilar.add(chain);
                }
            }else {
                //todo 这里加入class为了排除全是jdk链 默认排除 全是JDK类的链
                Map<ClassReference.Handle, ClassReference> classMap = new LinkedHashMap<>();
                for (ClassReference classReference : DataLoader.loadData(Paths.get("classes.dat"), new ClassReference.Factory())) {
                    classMap.put(classReference.getHandle(), classReference);
                }

                List<ClassReference.Handle> rt_jar_class = classMap.entrySet()
                        .stream()
                        .map(Map.Entry::getKey)
                        .limit(ConfigHelper.rt_jar_size)
                        .collect(Collectors.toList());
                Set<ClassReference.Handle> rt_jar_class_set = new HashSet<>(rt_jar_class);
                Iterator<GadgetChain> iterator = discoveredGadgets.iterator();
                while (iterator.hasNext()) {
                    GadgetChain chain = iterator.next();
                    //todo 为了让他们对象相等
                    List<ClassReference.Handle> chain_links = new ArrayList<>();
                    for (GadgetChainLink link : chain.links) {
                        chain_links.add(link.method.getClassReference());
                    }
                    boolean flag = false;
                    for (ClassReference.Handle chain_link : chain_links) {
                        if (!rt_jar_class_set.contains(chain_link)) {
                            flag = true;
                        }
                    }
                    if (!flag) {
                        iterator.remove();
                    }

                    if (chain.links.size() <= ConfigHelper.similarLevel) {
                        continue;
                    }
                    treeSimilar.add(chain);
                }
            }



            if (!treeSimilar.isEmpty()){
                Set<ArrayList<GadgetChainLink>> repeatSim = new HashSet<>();
                for (GadgetChain chain : treeSimilar){
                    ArrayList<GadgetChainLink> temp = new ArrayList<>(chain.links.subList(0,ConfigHelper.similarLevel));
                    temp.add(chain.links.get(chain.links.size()-1));
                    if(repeatSim.contains(temp)){
                        discoveredGadgets.remove(chain);
                    }
                    else {
                        repeatSim.add(temp);
                    }
                }
            }
        }



        //todo 测试 转换对象 输出html
        List<ResultInfo> resultInfoList = new ArrayList<>();
        //todo LinkedHashSet实现对象比较 去重
        Set<GadgetChain> newdiscoveredGadgets = new LinkedHashSet<>(discoveredGadgets);
        if (!discoveredGadgets.isEmpty()) {
            SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd-HH-mm");
            try (OutputStream outputStream = Files.newOutputStream(Paths.get("gadget-result/result_cache/gadget-chains-" + simpleDateFormat.format(new Date()) + ".txt"));
                 Writer writer = new OutputStreamWriter(outputStream, StandardCharsets.UTF_8)) {
                if (pathList != null) {
                    writer.write("Using classpath: " + Arrays.toString(pathList.toArray()) + "\n");
                }
                for (GadgetChain chain : newdiscoveredGadgets) {
                    // 解决type等
                    MethodReference.Handle method = chain.links.get(chain.links.size() - 1).method;
                    int taintedArgIndex = chain.links.get(chain.links.size() - 1).taintedArgIndex;
                    sinktype sinktype = new sinktype();
                    String type_Category = sinktype.type_Category(method, taintedArgIndex, inheritanceMap);

                    //todo 加入html输出
                    ResultInfo resultInfo = new ResultInfo();
                    List<String> links = new ArrayList<>();
                    for (int i = 0; i < chain.links.size(); i++) {
                        String linksres = String.format("  %s.%s%s (%d)%n",
                                chain.links.get(i).method.getClassReference().getName(),
                                chain.links.get(i).method.getName(),
                                chain.links.get(i).method.getDesc(),
                                chain.links.get(i).taintedArgIndex);
                        links.add(linksres);
                        ////这里是写txt
                        writer.write(linksres);
                    }
                    //这里是写txt换行
                    writer.write("\n");
                    //提取分割
                    int plusIndex = type_Category.indexOf(".");
                    String type = type_Category.substring(0, plusIndex);  // 提取定义信息
                    String Category = type_Category.substring(plusIndex + 1);  // 提取剩余字符串
                    //下面是写html
                    resultInfo.setType(type);
                    resultInfo.setVulName(Category);
                    resultInfo.setLinks(links);
                    resultInfoList.add(resultInfo);
                    //测试结束
                }
                writer.close();
                outputStream.close();
                //输出html文件
                ResultOutput.write(String.valueOf(Paths.get("gadget-result/gadget-chains.html")), resultInfoList);
            }

        }
        LOGGER.info("Found {} gadget chains.", newdiscoveredGadgets.size());
    }

    private static class GadgetChain {
        private final List<GadgetChainLink> links;

        private GadgetChain(List<GadgetChainLink> links) {
            this.links = links;
        }

        private GadgetChain(GadgetChain gadgetChain, GadgetChainLink link) {
            List<GadgetChainLink> links = new ArrayList<GadgetChainLink>(gadgetChain.links);
            links.add(link);
            this.links = links;
        }
        @Override
        public int hashCode() {
            return Objects.hash(links);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            // 自定义比较逻辑
            return true;
        }
    }

    private static class GadgetChainLink {
        private final MethodReference.Handle method;
        private final int taintedArgIndex;

        private GadgetChainLink(MethodReference.Handle method, int taintedArgIndex) {
            this.method = method;
            this.taintedArgIndex = taintedArgIndex;

        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            GadgetChainLink that = (GadgetChainLink) o;

            if (taintedArgIndex != that.taintedArgIndex) return false;
            return method != null ? method.equals(that.method) : that.method == null;
        }

        @Override
        public int hashCode() {
            int result = method != null ? method.hashCode() : 0;
            result = 31 * result + taintedArgIndex;
            return result;
        }
    }

    /**
     * Represents a collection of methods in the JDK that we consider to be "interesting". If a gadget chain can
     * successfully exercise one of these, it could represent anything as mundade as causing the target to make a DNS
     * query to full blown RCE.
     * @param method
     * @param argIndex
     * @param inheritanceMap
     * @return
     */
    // TODO: Parameterize this as a configuration option
    private boolean isSink(MethodReference.Handle method, int argIndex,
                           InheritanceMap inheritanceMap) {

        //通用Sink，不设定Sink则全部都挖掘
        if ((ConfigHelper.sinks.isEmpty() || ConfigHelper.sinks.stream().map(String::toUpperCase).collect(Collectors.toSet()).contains("JNDI")) && JNDISink(method, inheritanceMap)) {
            return true;
        }
        if ((ConfigHelper.sinks.isEmpty() || ConfigHelper.sinks.stream().map(String::toUpperCase).collect(Collectors.toSet()).contains("XXE")) && XXESink(method, inheritanceMap)) {
            return true;
        }
        if ((ConfigHelper.sinks.isEmpty() || ConfigHelper.sinks.stream().map(String::toUpperCase).collect(Collectors.toSet()).contains("EXEC")) && EXECSink(method, argIndex,inheritanceMap)) {
            return true;
        }
        if ((ConfigHelper.sinks.isEmpty() || ConfigHelper.sinks.stream().map(String::toUpperCase).collect(Collectors.toSet()).contains("FILEIO")) && FileIOSink(method,argIndex)) {
            return true;
        }

        if ((ConfigHelper.sinks.isEmpty() || ConfigHelper.sinks.stream().map(String::toUpperCase).collect(Collectors.toSet()).contains("REFLECT")) && ReflectSink(method, argIndex, inheritanceMap)) {
            return true;
        }
        if ((ConfigHelper.sinks.isEmpty() || ConfigHelper.sinks.stream().map(String::toUpperCase).collect(Collectors.toSet()).contains("JDBC")) && JDBCSink(method, argIndex, inheritanceMap)) {
            return true;
        }
        if ((ConfigHelper.sinks.isEmpty() || ConfigHelper.sinks.stream().map(String::toUpperCase).collect(Collectors.toSet()).contains("EL")) && ELSink(method, argIndex, inheritanceMap)) {
            return true;
        }
        if ((ConfigHelper.sinks.isEmpty() || ConfigHelper.sinks.stream().map(String::toUpperCase).collect(Collectors.toSet()).contains("SQL")) && isSQLInjectSink(method, argIndex, inheritanceMap)) {
            return true;
        }
        if ((ConfigHelper.sinks.isEmpty() || ConfigHelper.sinks.stream().map(String::toUpperCase).collect(Collectors.toSet()).contains("SSRF")) && SSRFSink(method)){
            return true;
        }
        if ((ConfigHelper.sinks.isEmpty() || ConfigHelper.sinks.stream().map(String::toUpperCase).collect(Collectors.toSet()).contains("SSTI")) && SSTISink(method)){
            return true;
        }
        if ((ConfigHelper.sinks.isEmpty() || ConfigHelper.sinks.stream().map(String::toUpperCase).collect(Collectors.toSet()).contains("DESERIALIZE")) && deserializeSink(method)) {
            return true;
        }
        if ((ConfigHelper.sinks.isEmpty() || ConfigHelper.sinks.stream().map(String::toUpperCase).collect(Collectors.toSet()).contains("XPATH")) && XpathSink(method)) {
            return true;
        }
        if ((ConfigHelper.sinks.isEmpty() || ConfigHelper.sinks.stream().map(String::toUpperCase).collect(Collectors.toSet()).contains("EXPRESSION")) && ExpressionSink(method)) {
            return true;
        }

        if ((ConfigHelper.sinks.isEmpty() || ConfigHelper.sinks.stream().map(String::toUpperCase).collect(Collectors.toSet()).contains("REDIRECT")) && RedirectSink(method,argIndex)){
            return true;
        }
        return false;
    }

    public boolean RedirectSink(MethodReference.Handle method,int argIndex){
        if (method.getClassReference().getName().equals("javax/servlet/http/HttpServletResponse")
                && method.getName().equals("sendRedirect")&&argIndex!=0) {
            return true;
        }
        if (method.getClassReference().getName().equals("org/springframework/web/servlet/ModelAndView")
                && method.getName().equals("<init>")) {
            return true;
        }
        return false;
    }

    public boolean ExpressionSink(MethodReference.Handle method) {
        if (method.getClassReference().getName().equals("org/springframework/beans/factory/config/BeanExpressionResolver")
                && method.getName().equals("evaluate")) {
            return true;
        }
        if (method.getClassReference().getName().equals("org/springframework/expression/ExpressionParser")
                && method.getName().equals("parseExpression")) {
            return true;
        }
        if (method.getClassReference().getName().equals("org/opensymphony/xwork2/util/ValueStack")
                && method.getName().equals("setValue")) {
            return true;
        }
        if (method.getClassReference().getName().equals("org/opensymphony/xwork2/util/ValueStack")
                && method.getName().equals("findValue")) {
            return true;
        }
        if (method.getClassReference().getName().equals("ognl/Ognl")
                && method.getName().equals("parseExpression")) {
            return true;
        }
        if (method.getClassReference().getName().equals("ognl/Ognl")
                && method.getName().equals("getValue")) {
            return true;
        }
        if (method.getClassReference().getName().equals("ognl/Ognl")
                && method.getName().equals("setValue")) {
            return true;
        }
        return false;
    }
    public boolean XpathSink(MethodReference.Handle method) {
        if (method.getClassReference().getName().equals("javax/xml/xpath/XPath")
                && method.getName().equals("evaluate")) {
            return true;
        }
        if (method.getClassReference().getName().equals("javax/xml/xpath/XPathExpression")
                && method.getName().equals("evaluate")) {
            return true;
        }
        return false;
    }
    public boolean deserializeSink(MethodReference.Handle method){
        if (method.getClassReference().getName().equals("com/alibaba/fastjson/JSON")
                && (method.getName().equals("parse")||method.getName().equals("parseArray")||method.getName().equals("parseObject"))) {
            return true;
        }
        if (method.getClassReference().getName().equals("com/alibaba/com/caucho/hessian/io/Hessian2Input")
                && (method.getName().equals("readObject"))) {//method.getName().equals("<init>")||
            return true;
        }
        if (method.getClassReference().getName().equals("java/io/ObjectInputStream")
                && method.getName().equals("readObject")&&ConfigHelper.readObjectissink) {
            return true;
        }
        if (method.getClassReference().getName().equals("com/fasterxml/jackson/databind/ObjectMapper")
                && (method.getName().equals("readValue")||method.getName().equals("enableDefaultTyping"))) {
            return true;
        }
        if (method.getClassReference().getName().equals("org/yaml/snakeyaml/Yaml")
                && (method.getName().equals("<init>")||method.getName().equals("load"))) {
            return true;
        }
        if (method.getClassReference().getName().equals("org/ho/yaml/Yaml")
                && method.getName().equals("load")) {
            return true;
        }
        if (method.getClassReference().getName().equals("org/ho/yaml/YamlDecoder")
                && method.getName().equals("<init>")) {
            return true;
        }
        if (method.getClassReference().getName().equals("com/esotericsoftware/yamlbeans/YamlReader")
                && method.getName().equals("read")) {
            return true;
        }
        if (method.getClassReference().getName().equals("java/beans/XMLDecoder")
                && method.getName().equals("readObject")) {
            return true;
        }
        if (method.getClassReference().getName().equals("com/thoughtworks/xstream/XStream")
                && method.getName().equals("fromXML")) {
            return true;
        }
        if (method.getClassReference().getName().equals("java/net/URLClassLoader")
                && method.getName().equals("findResource")) {
            return true;
        }
//        if (method.getClassReference().getName().equals("java/net/URLClassLoader")
//                && method.getName().equals("findClass")) {
//            return true;
//        }
//        if (method.getClassReference().getName().equals("java/net/URLClassLoader")
//                && method.getName().equals("findResources")) {
//            return true;
//        }
//        if (method.getClassReference().getName().equals("java/net/URLClassLoader")
//                && method.getName().equals("loadClass")) {
//            return true;
//        }
        return false;
    }

    public boolean JDBCSink(MethodReference.Handle method, int argIndex, InheritanceMap inheritanceMap) {
        if (method.getClassReference().getName().equals("javax/sql/DataSource")
                && method.getName().equals("getConnection")) {
            return true;
        }
        return false;
    }

    public boolean ReflectSink(MethodReference.Handle method, int argIndex, InheritanceMap inheritanceMap) {
        if (method.getClassReference().getName().equals("java/lang/reflect/Method")
                && method.getName().equals("invoke")) {
            return true;
        }
        if (method.getClassReference().getName().equals("java/lang/Class")
                && method.getName().equals("forName")
                && method.getDesc().equals("(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;")) {
            return true;
        }
        if ((method.getClassReference().getName().equals("com/sun/org/apache/xalan/internal/xsltc/trax/TemplatesImpl")
            ||method.getClassReference().getName().equals("javax/xml/transform/Templates"))
                && method.getName().equals("newTransformer")){
            return true;
        }

        if (method.getClassReference().getName().equals("java/net/URLClassLoader")
                && method.getName().equals("newInstance")) {
            return true;
        }


//!method.getClassReference().getName().equals("javax/management/loading/MLet")&&
        if (method.getClassReference().getName().equals("java/lang/ClassLoader")
                && method.getName().equals("defineClass")) {
            return true;
        }

        // Some groovy-specific sinks
        if (method.getClassReference().getName().equals("org/codehaus/groovy/runtime/InvokerHelper")
                && method.getName().equals("invokeMethod") && argIndex == 1) {
            return true;
        }

        if (inheritanceMap.isSubclassOf(method.getClassReference(),
                new ClassReference.Handle("groovy/lang/MetaClass"))
                && Arrays.asList("invokeMethod", "invokeConstructor", "invokeStaticMethod")
                .contains(method.getName())) {
            return true;
        }
        return false;
    }

    public boolean FileIOSink(MethodReference.Handle method,int argIndex) {
        if (method.getClassReference().getName().equals("java/io/FileOutputStream")
                && method.getName().equals("<init>")) {
            return true;
        }
        if (method.getClassReference().getName().equals("java/io/FileOutputStream")
                && method.getName().equals("write") && argIndex > 0) {
            return true;
        }
        if (method.getClassReference().getName().equals("java/nio/file/Files")
                && method.getName().equals("write") && argIndex > 0) {
            return true;
        }
        if (method.getClassReference().getName().equals("java/nio/file/Files")
                && (method.getName().equals("newInputStream")
                || method.getName().equals("newOutputStream")
                || method.getName().equals("newBufferedReader")
                || method.getName().equals("newBufferedWriter")
                || method.getName().equals("readAllBytes"))) {
            return true;
        }
        if (method.getClassReference().getName().equals("java/nio/file/Paths") && method.getName().equals("get")) {
            return true;
        }
        if (method.getClassReference().getName().equals("java/io/File")
                && method.getName().equals("createTempFile") && argIndex > 0) {
            return true;
        }
        if (method.getClassReference().getName().equals("org/springframework/web/multipart/MultipartFile") && method.getName()
                .equals("transferTo")) {
            return true;
        }
        return false;
    }

    //exec测试均通过
    public boolean EXECSink(MethodReference.Handle method, int argIndex,InheritanceMap inheritanceMap) {
        if (method.getClassReference().getName().equals("java/lang/Runtime")&&
                        method.getName().equals("exec")) {
            return true;
        }
        //就只能污点分析到这里 除非添加白名单
        if (method.getClassReference().getName().equals("java/lang/ProcessBuilder")
                && (method.getName().equals("command")||method.getName().equals("<init>"))) {
            return true;
        }
        if (method.getClassReference().getName().equals("javax/script/ScriptEngine")
                && method.getName().equals("eval")) {
            return true;
        }
        if (method.getClassReference().getName().equals("groovy/lang/GroovyShell")
                && method.getName().equals("evaluate")) {
            return true;
        }
        if (method.getClassReference().getName().equals("org/mozilla/javascript/Context")
                && method.getName().equals("evaluateString")) {
            return true;
        }

        return false;
    }

    public boolean SSTISink(MethodReference.Handle method){
        //Velocity模板
        if (method.getClassReference().getName().equals("org/apache/velocity/app/Velocity")
                && (method.getName().equals("evaluate") || method.getName().equals("mergeTemplate"))) {
            return true;
        }
        //Thymeleaf模板引擎
        if (method.getClassReference().getName().equals("org.thymeleaf.TemplateEngine")
                && (method.getName().equals("process") || method.getName().equals("processTemplate"))) {
            return true;
        }
        //Apache FreeMarker模板
        if (method.getClassReference().getName().equals("freemarker.template.Template")
                && method.getName().equals("process")) {
            return true;
        }
        if (method.getClassReference().getName().equals("org/mvel/MVEL")
                && method.getName().equals("eval")) {
            return true;
        }
        return false;
    }
    public boolean SSRFSink(MethodReference.Handle method){
        if (method.getClassReference().getName().equals("javax/imageio/ImageIO")&&
                method.getName().equals("read")) {
            return true;
        }
        if (method.getClassReference().getName().equals("java/net/URL")&& (method.getName().equals("openConnection") || method.getName().equals("openStream"))) {
            return true;
        }
        if (method.getClassReference().getName().equals("org/apache/http/client/fluent/Request")
                && method.getName().equals("execute")) {
            return true;
        }
        if (method.getClassReference().getName().equals("org/apache/commons/httpclient/HttpClient")
                && (method.getName().equals("executeMethod")||method.getName().equals("execute"))) {
            return true;
        }
        if (method.getClassReference().getName().equals("java/net/URLConnection")
                && (method.getName().equals("connect") || method.getName().equals("getInputStream"))) {
            return true;
        }
        if (method.getClassReference().getName().equals("org/jsoup/Jsoup")
                && method.getName().equals("connect")) {
            return true;
        }
        if (method.getClassReference().getName().equals("com/squareup/okhttp/Call")
                && method.getName().equals("execute")) {
            return true;
        }
        if (method.getClassReference().getName().equals("org/apache/commons/io/IOUtils")
                && method.getName().equals("toByteArray")) {
            return true;
        }
        if (method.getClassReference().getName().equals("org/apache/http/impl/nio/client/CloseableHttpAsyncClient")
                && method.getName().equals("execute")) {
            return true;
        }
        if (method.getClassReference().getName().equals("org/springframework/web/client/RestTemplate")
                && method.getName().equals("exchange")) {
            return true;
        }
        if (method.getClassReference().getName().equals("org/springframework/web/reactive/function/client/WebClient")
                && method.getName().equals("exchange")) {
            return true;
        }
        if (method.getClassReference().getName().equals("org/springframework/web/client/AsyncRestTemplate")
                && method.getName().equals("exchange")) {
            return true;
        }
        if (method.getClassReference().getName().equals("java/net/MulticastSocket")
                && method.getName().equals("send")) {
            return true;
        }
        if (method.getClassReference().getName().equals("java/net/DatagramSocket")
                && method.getName().equals("send")) {
            return true;
        }
        if (method.getClassReference().getName().equals("java/net/Socket")
                && ((method.getName().equals("connect"))||method.getName().equals("<init>"))) {
            return true;
        }
        if (method.getClassReference().getName().equals("org/apache/http/impl/client/CloseableHttpClient")
                && method.getName().equals("execute")) {
            return true;
        }
        if (method.getClassReference().getName().equals("org/apache/http/impl/client/DefaultHttpClient")
                && method.getName().equals("execute")) {
            return true;
        }
        if (((method.getClassReference().getName().equals("okhttp3/Request$Builder"))|| method.getClassReference().getName().equals("okhttp/Request$Builder"))
                && method.getName().equals("url")) {
            return true;
        }
        if (method.getClassReference().getName().equals("okhttp3/Call")
                && (method.getName().equals("execute"))||method.getName().equals("okhttp/Call")) {
            return true;
        }

        return false;
    }


    public boolean XXESink(MethodReference.Handle method, InheritanceMap inheritanceMap) {
        if ((inheritanceMap.isSubclassOf(method.getClassReference(),
                        new ClassReference.Handle("javax/xml/parsers/DocumentBuilder"))||
                method.getClassReference().getName().equals("javax/xml/parsers/DocumentBuilder")
        )&& method.getName().equals("parse")) {
            return true;
        }
        if ((inheritanceMap.isSubclassOf(method.getClassReference(),
                        new ClassReference.Handle("org/jdom/input/SAXBuilder"))||
                method.getClassReference().getName().equals("org/jdom/input/SAXBuilder")
        )&& method.getName().equals("build")) {
            return true;
        }
        if ((inheritanceMap.isSubclassOf(method.getClassReference(),
                new ClassReference.Handle("org/apache/commons/digester3/Digester"))||
                method.getClassReference().getName().equals("org/apache/commons/digester3/Digester")
        )&& method.getName().equals("parse")) {
            return true;
        }
        if ((inheritanceMap.isSubclassOf(method.getClassReference(),
                new ClassReference.Handle("org/dom4j/DocumentHelper"))||
                method.getClassReference().getName().equals("org/dom4j/DocumentHelper")
                )&& method.getName().equals("parseText")) {
            return true;
        }
        if ((inheritanceMap.isSubclassOf(method.getClassReference(),
                        new ClassReference.Handle("javax/xml/parsers/SAXParser"))||
                method.getClassReference().getName().equals("javax/xml/parsers/SAXParser")
        )&& method.getName().equals("parse")) {
            return true;
        }
        if ((inheritanceMap.isSubclassOf(method.getClassReference(),
                        new ClassReference.Handle("org/dom4j/io/SAXReader"))||
                method.getClassReference().getName().equals("org/dom4j/io/SAXReader")
        ) && method.getName().equals("read")) {
            return true;
        }
        if ((inheritanceMap.isSubclassOf(method.getClassReference(),
                        new ClassReference.Handle("javax/xml/transform/sax/SAXTransformerFactory"))||
                method.getClassReference().getName().equals("javax/xml/transform/sax/SAXTransformerFactory")
        )&& method.getName().equals("newTransformerHandler")) {
            return true;
        }
        if ((inheritanceMap.isSubclassOf(method.getClassReference(),
                        new ClassReference.Handle("javax/xml/validation/SchemaFactory"))||
                method.getClassReference().getName().equals("javax/xml/validation/SchemaFactory")
        )&& method.getName().equals("newSchema")) {
            return true;
        }
        if ((inheritanceMap.isSubclassOf(method.getClassReference(),
                        new ClassReference.Handle("javax/xml/transform/Transformer"))||
                method.getClassReference().getName().equals("javax/xml/transform/Transformer")
        )&& method.getName().equals("transform")) {
            return true;
        }
        if ((inheritanceMap.isSubclassOf(method.getClassReference(),
                        new ClassReference.Handle("javax/xml/bind/Unmarshaller"))||
                method.getClassReference().getName().equals("javax/xml/bind/Unmarshaller")
        )&& method.getName().equals("unmarshal")) {
            return true;
        }
        if ((inheritanceMap.isSubclassOf(method.getClassReference(),
                        new ClassReference.Handle("javax/xml/validation/Validator"))||
                method.getClassReference().getName().equals("javax/xml/validation/Validator")
        )&& method.getName().equals("validate")) {
            return true;
        }
        if ((inheritanceMap.isSubclassOf(method.getClassReference(),
                        new ClassReference.Handle("org/xml/sax/XMLReader"))||
                method.getClassReference().getName().equals("org/xml/sax/XMLReader")
        ) && method.getName().equals("parse")) {
            return true;
        }
        return false;
    }

    public boolean JNDISink(MethodReference.Handle method, InheritanceMap inheritanceMap) {
        //这里是获取子类是否继承了父类 基本继承了 就会super调到父类 但是一些并不完善 但是存在很多结果.......... 待完善
        if ((inheritanceMap.isSubclassOf(method.getClassReference(),
                new ClassReference.Handle("java/rmi/registry/Registry")) ||
                inheritanceMap.isSubclassOf(method.getClassReference(),
                        new ClassReference.Handle("javax/naming/Context")) ||
                method.getClassReference().getName().equals("javax/naming/Context") ||
                method.getClassReference().getName().equals("java/rmi/registry/Registry"))
                && (method.getName().equals("lookup")||method.getName().equals("bind"))) {
            return true;
        }
        return false;
    }

    public boolean ELSink(MethodReference.Handle method, int argIndex, InheritanceMap inheritanceMap) {
        if ((inheritanceMap.isSubclassOf(method.getClassReference(),
                new ClassReference.Handle("javax/validation/ConstraintValidatorContext")) ||
                inheritanceMap.isSubclassOf(method.getClassReference(),
                        new ClassReference.Handle("org/hibernate/validator/internal/engine/constraintvalidation/ConstraintValidatorContextImpl"))||
                method.getClassReference().getName().equals("javax/validation/ConstraintValidatorContext")||
                method.getClassReference().getName().equals("org/hibernate/validator/internal/engine/constraintvalidation/ConstraintValidatorContextImpl")) &&
                argIndex == 1 &&
                method.getName().equals("buildConstraintViolationWithTemplate")) {
            return true;
        }
        if ((inheritanceMap.isSubclassOf(method.getClassReference(),
                new ClassReference.Handle("org/springframework/expression/ExpressionParser")) ||
                inheritanceMap.isSubclassOf(method.getClassReference(),
                        new ClassReference.Handle("org/springframework/expression/spel/standard/SpelExpressionParser"))||
                method.getClassReference().getName().equals("org/springframework/expression/ExpressionParser")||
                method.getClassReference().getName().equals("org/springframework/expression/spel/standard/SpelExpressionParser")) &&
                argIndex == 1 &&
                (method.getName().equals("parseExpression") || method.getName().equals("parseRaw"))) {
            return true;
        }
        if ((inheritanceMap.isSubclassOf(method.getClassReference(),
                new ClassReference.Handle("javax/el/ELProcessor"))||
                method.getClassReference().getName().equals("javax/el/ELProcessor")&&
                argIndex == 1 && method.getName().equals("eval"))
                ||
                inheritanceMap.isSubclassOf(method.getClassReference(),
                        new ClassReference.Handle("javax/el/ExpressionFactory")) ||
                        method.getClassReference().getName().equals("javax/el/ExpressionFactory")&&
                        argIndex == 2 && method.getName().equals("createValueExpression")) {
            return true;
        }
        // 20210428
        if ((inheritanceMap.isSubclassOf(method.getClassReference(),
                new ClassReference.Handle("org/thymeleaf/standard/expression/StandardExpressionParser"))||
                method.getClassReference().getName().equals("org/thymeleaf/standard/expression/StandardExpressionParser")
        ) && method.getName().equals("parseExpression")) {
            return true;
        }
        // 最终Sink点StandardExpressionParser，将Sink提前
        if ((inheritanceMap.isSubclassOf(method.getClassReference(),new ClassReference.Handle("org/springframework/web/servlet/DispatcherServlet"))||
                method.getClassReference().getName().equals("org/springframework/web/servlet/DispatcherServlet"))
                && (method.getName().equals("render"))) {
            return true;
        }

        return false;
    }


    public boolean isSQLInjectSink(MethodReference.Handle method, int argIndex,
                                    InheritanceMap inheritanceMap) {
        if (inheritanceMap.isSubclassOf(method.getClassReference(),
                new ClassReference.Handle("org/springframework/jdbc/core/StatementCallback")) &&
                method.getName().equals("doInStatement") && argIndex!=0) {
            return true;
        }
        if (method.getClassReference().getName().equals("org/springframework/jdbc/core/JdbcTemplate")
                && (method.getName().equals("update")||method.getName().equals("execute")||method.getName().equals("query")
                ||method.getName().equals("queryForStream")||method.getName().equals("queryForList")||method.getName().equals("queryForMap")
                ||method.getName().equals("queryForObject"))&&argIndex!=0) {
            return true;
        }
        if (method.getClassReference().getName().equals("java/sql/Statement")
                && argIndex!=0 && (method.getName().equals("executeQuery")||method.getName().equals("executeUpdate")||method.getName().equals("execute"))) {
            return true;
        }
        return false;
    }

    public static void main(String[] args) throws Exception {
        GadgetChainDiscovery gadgetChainDiscovery = new GadgetChainDiscovery(new JavaDeserializationConfig());
        gadgetChainDiscovery.discover(null);
    }
}
