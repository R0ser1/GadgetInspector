package gadgetinspector;

import gadgetinspector.config.GIConfig;
import gadgetinspector.config.JavaDeserializationConfig;
import gadgetinspector.data.*;
import org.objectweb.asm.*;
import org.objectweb.asm.commons.JSRInlinerAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class PassthroughDiscovery {

    private static final Logger LOGGER = LoggerFactory.getLogger(PassthroughDiscovery.class);

    private final Map<MethodReference.Handle, Set<MethodReference.Handle>> methodCalls = new HashMap<>();
    private Map<MethodReference.Handle, Set<Integer>> passthroughDataflow;

    public void discover(final ClassResourceEnumerator classResourceEnumerator, final GIConfig config) throws IOException {
        //把methods.dat 加载传递  其中key 为classReference name desc ||  value为前面说的加一个是否为静态方法
        Map<MethodReference.Handle, MethodReference> methodMap = DataLoader.loadMethods();
        //把classes.data 加载 key为class名 value为classReference 包括name superclass interface members【属性】
        Map<ClassReference.Handle, ClassReference> classMap = DataLoader.loadClasses();
        // 继承类 一个class 的父类和接口 然后使用InheritanceMap包装  其中包含inheritanceMap subClassMap 而后者是父类与子类的映射 key为父类  value是子类
        InheritanceMap inheritanceMap = InheritanceMap.load();
        // 分析了类下面的方法 通过methodCalls存储了类下面的方法作为KEY   里面待调用的方法 为Vlue  但是这个classResourceByName只是把类当作class value为class和它的classloader
        Map<String, ClassResourceEnumerator.ClassResource> classResourceByName = discoverMethodCalls(classResourceEnumerator);
        //拓扑排序算法 得到基于DFS逆拓扑排序的Methods
        List<MethodReference.Handle> sortedMethods = topologicallySortMethodCalls();

         passthroughDataflow = calculatePassthroughDataflow(classResourceByName, classMap, inheritanceMap, sortedMethods,
                config.getSerializableDecider(methodMap, inheritanceMap));
    }

    private Map<String, ClassResourceEnumerator.ClassResource> discoverMethodCalls(final ClassResourceEnumerator classResourceEnumerator) throws IOException {
        Map<String, ClassResourceEnumerator.ClassResource> classResourcesByName = new HashMap<>();
        for (ClassResourceEnumerator.ClassResource classResource : classResourceEnumerator.getAllClasses()) {
            try (InputStream in = classResource.getInputStream()) {
                ClassReader cr = new ClassReader(in);
                try {
                    //重写MethodVisitor 分析待分析的类以及类下的方法存入methodCalls
                    MethodCallDiscoveryClassVisitor visitor = new MethodCallDiscoveryClassVisitor(Opcodes.ASM9);
                    cr.accept(visitor, ClassReader.EXPAND_FRAMES);

                    classResourcesByName.put(visitor.getName(), classResource);
                } catch (Exception e) {
                    LOGGER.error("Error analyzing: " + classResource.getName(), e);
                }
            }
        }
        return classResourcesByName;
    }
    private List<MethodReference.Handle> topologicallySortMethodCalls() {
        //这里赋值 没看懂 为什么要遍历 个人觉得都是一样的 先记录一下吧。
        Map<MethodReference.Handle, Set<MethodReference.Handle>> outgoingReferences = new HashMap<>();
        for (Map.Entry<MethodReference.Handle, Set<MethodReference.Handle>> entry : methodCalls.entrySet()) {
            MethodReference.Handle method = entry.getKey();
            outgoingReferences.put(method, new HashSet<>(entry.getValue()));
        }

        //拓扑排序算法 得到逆拓扑排序的Methods
        LOGGER.debug("Performing topological sort...");
        Set<MethodReference.Handle> dfsStack = new HashSet<>();
        Set<MethodReference.Handle> visitedNodes = new HashSet<>();
        List<MethodReference.Handle> sortedMethods = new ArrayList<>(outgoingReferences.size());
        for (MethodReference.Handle root : outgoingReferences.keySet()) {
            dfsTsort(outgoingReferences, sortedMethods, visitedNodes, dfsStack, root);
        }
        LOGGER.debug(String.format("Outgoing references %d, sortedMethods %d", outgoingReferences.size(), sortedMethods.size()));

        return sortedMethods;
    }

    private static Map<MethodReference.Handle, Set<Integer>> calculatePassthroughDataflow(Map<String, ClassResourceEnumerator.ClassResource> classResourceByName,
                                                                                          Map<ClassReference.Handle, ClassReference> classMap,
                                                                                          InheritanceMap inheritanceMap,
                                                                                          List<MethodReference.Handle> sortedMethods,
                                                                                          SerializableDecider serializableDecider) throws IOException {

        //使用支持高并发的ConcurrentHashMap代替hashmap 提高效率
        final Map<MethodReference.Handle, Set<Integer>> passthroughDataflow = new ConcurrentHashMap<>();
        sortedMethods.parallelStream().forEach(method -> {
            // 跳过静态代码块
            if (method.getName().equals("<clinit>")) {
                return;
            }
            ClassResourceEnumerator.ClassResource classResource = classResourceByName.get(method.getClassReference().getName());
            try (InputStream inputStream = classResource.getInputStream()) {
                ClassReader cr = new ClassReader(inputStream);
                try {
                    PassthroughDataflowClassVisitor cv = new PassthroughDataflowClassVisitor(classMap, inheritanceMap,
                            passthroughDataflow, serializableDecider, Opcodes.ASM9, method);
                    cr.accept(cv, ClassReader.EXPAND_FRAMES);
                    passthroughDataflow.put(method, cv.getReturnTaint());
                } catch (Exception e) {
                    LOGGER.error("Exception analyzing " + method.getClassReference().getName(), e);
                }
            } catch (IOException e) {
                LOGGER.error("Unable to analyze " + method.getClassReference().getName(), e);
            }
        });
        return passthroughDataflow;
    }

    private class MethodCallDiscoveryClassVisitor extends ClassVisitor {
        public MethodCallDiscoveryClassVisitor(int api) {
            super(api);
        }

        private String name = null;

        @Override
        public void visit(int version, int access, String name, String signature,
                          String superName, String[] interfaces) {
            super.visit(version, access, name, signature, superName, interfaces);
            if (this.name != null) {
                throw new IllegalStateException("ClassVisitor already visited a class!");
            }
            this.name = name;
        }

        public String getName() {
            return name;
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String desc,
                                         String signature, String[] exceptions) {
            MethodVisitor mv = super.visitMethod(access, name, desc, signature, exceptions);
            /*
            重写MethodVisitor  分析类 以及类下的方法存入methodCalls
            */
            MethodCallDiscoveryMethodVisitor modelGeneratorMethodVisitor = new MethodCallDiscoveryMethodVisitor(
                    api, mv, this.name, name, desc);
            /*
                交给JSRInlinerAdapter适配器........具体为止 没学过 记一下  asm老师说JSR已经过时不用
            */
            return new JSRInlinerAdapter(modelGeneratorMethodVisitor, access, name, desc, signature, exceptions);
        }

        @Override
        public void visitEnd() {
            super.visitEnd();
        }
    }

    private class MethodCallDiscoveryMethodVisitor extends MethodVisitor {
        private final Set<MethodReference.Handle> calledMethods;

        public MethodCallDiscoveryMethodVisitor(final int api, final MethodVisitor mv,
                                           final String owner, String name, String desc) {
            super(api, mv);

            this.calledMethods = new HashSet<>();
            // methodCalls 存入的是 待分析的类名 方法名 方法描述符 作为KEY
            // 传入calledMethods作为Value 他是待分析类下面待调用的类 以及方法 方法描述符
            methodCalls.put(new MethodReference.Handle(new ClassReference.Handle(owner), name, desc), calledMethods);
        }

        @Override
        public void visitMethodInsn(int opcode, String owner, String name, String desc, boolean itf) {
            calledMethods.add(new MethodReference.Handle(new ClassReference.Handle(owner), name, desc));
            super.visitMethodInsn(opcode, owner, name, desc, itf);
        }
    }

    public void save() throws IOException {
        if (passthroughDataflow == null) {
            throw new IllegalStateException("Save called before discover()");
        }

        DataLoader.saveData(Paths.get("passthrough.dat"), new PassThroughFactory(), passthroughDataflow.entrySet());
    }

    public static Map<MethodReference.Handle, Set<Integer>> load() throws IOException {
        Map<MethodReference.Handle, Set<Integer>> passthroughDataflow = new HashMap<>();
        for (Map.Entry<MethodReference.Handle, Set<Integer>> entry : DataLoader.loadData(Paths.get("passthrough.dat"), new PassThroughFactory())) {
            passthroughDataflow.put(entry.getKey(), entry.getValue());
        }
        return passthroughDataflow;
    }

    public static class PassThroughFactory implements DataFactory<Map.Entry<MethodReference.Handle, Set<Integer>>> {

        @Override
        public Map.Entry<MethodReference.Handle, Set<Integer>> parse(String[] fields) {
            ClassReference.Handle clazz = new ClassReference.Handle(fields[0]);
            MethodReference.Handle method = new MethodReference.Handle(clazz, fields[1], fields[2]);

            Set<Integer> passthroughArgs = new HashSet<>();
            for (String arg : fields[3].split(",")) {
                if (arg.length() > 0) {
                    passthroughArgs.add(Integer.parseInt(arg));
                }
            }
            return new AbstractMap.SimpleEntry<>(method, passthroughArgs);
        }

        @Override
        public String[] serialize(Map.Entry<MethodReference.Handle, Set<Integer>> entry) {
            if (entry.getValue().size() == 0) {
                return null;
            }

            final String[] fields = new String[4];
            fields[0] = entry.getKey().getClassReference().getName();
            fields[1] = entry.getKey().getName();
            fields[2] = entry.getKey().getDesc();

            StringBuilder sb = new StringBuilder();
            for (Integer arg : entry.getValue()) {
                sb.append(Integer.toString(arg));
                sb.append(",");
            }
            fields[3] = sb.toString();

            return fields;
        }
    }

    private static void dfsTsort(Map<MethodReference.Handle, Set<MethodReference.Handle>> outgoingReferences,
                                    List<MethodReference.Handle> sortedMethods, Set<MethodReference.Handle> visitedNodes,
                                    Set<MethodReference.Handle> stack, MethodReference.Handle node) {
        /*
        node:当前正在处理的方法句柄
        stack:当前DFS搜索的路径上的方法句柄的集合
        visitedNodes:存储已经访问过的方法句柄的集合
        sortedMethods:拓扑排序后的方法句柄列表，按照执行顺序排列
        outgoingReferences:存储了所有方法句柄的依赖关系的映射表，它的键是某个方法句柄，值是该方法句柄所依赖的其他方法句柄的集合
         */

        //而它的主要作用是为了防止出现环
        if (stack.contains(node)) {
            return;
        }
        //如果当前节点在visitedNodes中已经存在，说明该节点已经被访问过，直接返回，因为已经确定了该节点的排序位置。
        if (visitedNodes.contains(node)) {
            return;
        }
        //获取该方法的所有边  也就是子方法
        Set<MethodReference.Handle> outgoingRefs = outgoingReferences.get(node);
        if (outgoingRefs == null) {
            return;
        }
        //将节点加入stack 表示访问
        stack.add(node);
        //对于当前节点的每个出边，递归地进行DFS搜索，处理每个子节点的拓扑排序。
        for (MethodReference.Handle child : outgoingRefs) {
            dfsTsort(outgoingReferences, sortedMethods, visitedNodes, stack, child);
        }

        stack.remove(node);
        visitedNodes.add(node);
        sortedMethods.add(node);
    }

    private static class PassthroughDataflowClassVisitor extends ClassVisitor {

        Map<ClassReference.Handle, ClassReference> classMap;
        private final MethodReference.Handle methodToVisit;
        private final InheritanceMap inheritanceMap;
        private final Map<MethodReference.Handle, Set<Integer>> passthroughDataflow;
        private final SerializableDecider serializableDecider;

        private String name;
        private PassthroughDataflowMethodVisitor passthroughDataflowMethodVisitor;

        public PassthroughDataflowClassVisitor(Map<ClassReference.Handle, ClassReference> classMap,
                InheritanceMap inheritanceMap, Map<MethodReference.Handle, Set<Integer>> passthroughDataflow,
                SerializableDecider serializableDecider, int api, MethodReference.Handle methodToVisit) {
            /*
            classMap:key为class名 value为classReference 包括name superclass interface members【属性】
            inheritanceMap:继承类 其中包含inheritanceMap subClassMap 而后者是父类与子类的映射 key为父类  value是子类 前者Key:class Value:父类和接口
            passthroughDataflow:
            serializableDecider:决策者
            api:asm版本
            methodToVisit:从sortedMethods 遍历的方法
            */
            super(api);
            this.classMap = classMap;
            this.inheritanceMap = inheritanceMap;
            this.methodToVisit = methodToVisit;
            this.passthroughDataflow = passthroughDataflow;
            this.serializableDecider = serializableDecider;
        }

        @Override
        public void visit(int version, int access, String name, String signature,
                          String superName, String[] interfaces) {
            super.visit(version, access, name, signature, superName, interfaces);
            this.name = name;
            if (!this.name.equals(methodToVisit.getClassReference().getName())) {
                throw new IllegalStateException("Expecting to visit " + methodToVisit.getClassReference().getName() + " but instead got " + this.name);
            }
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String desc,
                                         String signature, String[] exceptions) {
            // 不是目标观察的method需要跳过，上一步得到的method都是有调用关系的method才需要数据流分析
            if (!name.equals(methodToVisit.getName()) || !desc.equals(methodToVisit.getDesc())) {
                return null;
            }
            if (passthroughDataflowMethodVisitor != null) {
                throw new IllegalStateException("Constructing passthroughDataflowMethodVisitor twice!");
            }

            MethodVisitor mv = super.visitMethod(access, name, desc, signature, exceptions);
            passthroughDataflowMethodVisitor = new PassthroughDataflowMethodVisitor(
                    classMap, inheritanceMap, this.passthroughDataflow, serializableDecider,
                    api, mv, this.name, access, name, desc, signature, exceptions);

            return new JSRInlinerAdapter(passthroughDataflowMethodVisitor, access, name, desc, signature, exceptions);
        }

        public Set<Integer> getReturnTaint() {
            if (passthroughDataflowMethodVisitor == null) {
                throw new IllegalStateException("Never constructed the passthroughDataflowmethodVisitor!");
            }
            return passthroughDataflowMethodVisitor.returnTaint;
        }
    }

    private static class PassthroughDataflowMethodVisitor extends TaintTrackingMethodVisitor<Integer> {

        private final Map<ClassReference.Handle, ClassReference> classMap;
        private final InheritanceMap inheritanceMap;
        private final Map<MethodReference.Handle, Set<Integer>> passthroughDataflow;
        private final SerializableDecider serializableDecider;

        private final int access;
        private final String desc;
        private final Set<Integer> returnTaint;

        //todo: 解决数组问题 使用state transitions
        protected int state;
        protected final static int SEEN_NOTHING = 0;
        protected static final int SEEN_ANEWARRAY= 1;
        protected static final int SEEN_DUP = 2;
        protected static final int SEEN_ICONST = 3;
        protected static final int SEEN_ALOAD = 4;
        protected static final int SEEN_AASTORE = 5;

        //下面解决是是byte..
        private int state2;
        protected final static int SEEN2_NOTHING = 0;
        protected static final int SEEN2_NEWARRAY= 1;
        protected static final int SEEN2_DUP = 2;
        protected static final int SEEN2_ICONST = 3;
        protected static final int SEEN2_ILOAD = 4;
        protected static final int SEEN2_BASTORE = 5;

        //解决new 问题
        protected int state4;
        protected final static int SEEN4_NOTHING = 0;
        protected static final int SEEN4_NEW= 1;
        protected static final int SEEN4_DUP = 2;
        protected static final int SEEN4_ALOAD = 3;
        protected static final int SEEN4_ASTORE = 4;

        public PassthroughDataflowMethodVisitor(Map<ClassReference.Handle, ClassReference> classMap,
                InheritanceMap inheritanceMap, Map<MethodReference.Handle,
                Set<Integer>> passthroughDataflow, SerializableDecider serializableDeciderMap, int api, MethodVisitor mv,
                String owner, int access, String name, String desc, String signature, String[] exceptions) {
            super(inheritanceMap, passthroughDataflow, api, mv, owner, access, name, desc, signature, exceptions);
            this.classMap = classMap;
            this.inheritanceMap = inheritanceMap;
            this.passthroughDataflow = passthroughDataflow;
            this.serializableDecider = serializableDeciderMap;
            this.access = access;
            this.desc = desc;
            returnTaint = new HashSet<>();
        }
        //visitCode 进入方法体调用
        @Override
        public void visitCode() {
            //先调用父类的visitCode 先初始化根据方法 以及arg判断需要占用的localVars
            super.visitCode();
            /*
            localIndex: 本地变量索引
            argIndex:参数索引
             */
            int localIndex = 0;
            int argIndex = 0;
            /*
            只有当 this.access 中不包含 ACC_STATIC 位时，才会返回 0.也就代表了当前方位不为静态方法。为实例。
            因为静态方法本身是不需要存储this的
            */
            if ((this.access & Opcodes.ACC_STATIC) == 0) {
                setLocalTaint(localIndex, argIndex);
                localIndex += 1;
                argIndex += 1;
            }
            for (Type argType : Type.getArgumentTypes(desc)) {
                setLocalTaint(localIndex, argIndex);
                // 根据参数类型 获取参数占用localVar的大小
                localIndex += argType.getSize();
                argIndex += 1;
            }
        }
        @Override
        public void visitVarInsn(int opcode, int var) {
            super.visitVarInsn(opcode, var);
            if (opcode==Opcodes.ALOAD&&state==SEEN_ICONST){
                state=SEEN_ALOAD;
            }
            if (opcode==Opcodes.ILOAD&&state2==SEEN2_ICONST){
                state2=SEEN2_ILOAD;
            }
            if (opcode==Opcodes.ALOAD&&state4==SEEN4_DUP){
                state4=SEEN4_ALOAD;
                super.visitVar_new(state4);
                state4=SEEN4_NOTHING;
            }
        }

        @Override
        public void visitTypeInsn(int opcode, String type) {
            if (opcode==Opcodes.ANEWARRAY){
                state=SEEN_ANEWARRAY;
            }
            if (opcode==Opcodes.NEW){
                state4=SEEN4_NEW;
            }
            super.visitTypeInsn(opcode, type);
        }
        @Override
        public void visitIntInsn(int opcode, int operand) {
            if (opcode==Opcodes.NEWARRAY){
                state2=SEEN2_NEWARRAY;
            }
            super.visitIntInsn(opcode, operand);
        }

        @Override
        public void visitInsn(int opcode) {
            switch (opcode){
                case Opcodes.IRETURN:
                case Opcodes.FRETURN:
                case Opcodes.ARETURN:
                    //从栈顶 获取刚刚入栈（第二步中visitVarInsn从本地变量表获取的参数索引）的参数索引，并存储到returnTaint中 参数为1就表示会污染返回值
                    returnTaint.addAll(getStackTaint(0));
                    break;
                case Opcodes.LRETURN:
                case Opcodes.DRETURN:
                    // 返回污点里保存栈顶元素（size为2）
                    returnTaint.addAll(getStackTaint(1));
                    break;
                case Opcodes.RETURN:
                    break;
                case Opcodes.DUP:
                    if (state==SEEN_ANEWARRAY){
                        state=SEEN_DUP;
                    }
                    if (state2==SEEN2_NEWARRAY){
                        state2=SEEN2_DUP;
                    }
                    if (state4==SEEN4_NEW){
                        state4=SEEN4_DUP;
                    }
                case Opcodes.ICONST_M1:
                case Opcodes.ICONST_0:
                case Opcodes.ICONST_1:
                case Opcodes.ICONST_2:
                case Opcodes.ICONST_3:
                case Opcodes.ICONST_4:
                case Opcodes.ICONST_5:
                case Opcodes.FCONST_0:
                case Opcodes.FCONST_1:
                case Opcodes.FCONST_2:
                    if (state==SEEN_DUP){
                        state=SEEN_ICONST;
                    }
                    if (state2==SEEN2_DUP){
                        state2=SEEN2_ICONST;
                    }
                case Opcodes.AASTORE:
                    if (state==SEEN_ALOAD){
                        super.visitInsn_array(state);
                        state=SEEN_NOTHING;
                        break;
                    }
                case Opcodes.BASTORE:
                    if (state2==SEEN2_ILOAD){
                        super.visitInsn_array(state2);
                        state2=SEEN2_NOTHING;
                        break;
                    }
                default:
                    break;
            }

            super.visitInsn(opcode);
        }

        @Override
        public void visitFieldInsn(int opcode, String owner, String name, String desc) {

            switch (opcode) {
                case Opcodes.GETSTATIC:
                    break;
                case Opcodes.PUTSTATIC:
                    break;
                    //该指令将一个对象引用从操作数栈中弹出，并根据指定的索引从该对象中获取相应的字段的值，然后将该值压入操作数栈上。
                case Opcodes.GETFIELD:
                    Type type = Type.getType(desc);
                    // 根据描述符获取属性的类型 非long double 占用空间即为1
                    if (type.getSize() == 1) {

                        Boolean isTransient = null;
                        // If a field type could not possibly be serialized, it's effectively transient
                        // 主要判断调用的字段类型是否可以被反序列化 【静态字段、transient字段等】
                        //transient关键字可以用来修饰字段，表示该字段不应该被序列化
                        if (!couldBeSerialized(serializableDecider, inheritanceMap, new ClassReference.Handle(type.getInternalName()))) {
                            isTransient = Boolean.TRUE;
                        } else {
                            //如果调用字段可以序列化就进来，取当前类实例的所有字段，找出调用的字段，判断是否被标识了transient 包含返回true 否则为false
                            ClassReference clazz = classMap.get(new ClassReference.Handle(owner));
                            while (clazz != null) {
                                for (ClassReference.Member member : clazz.getMembers()) {
                                    if (member.getName().equals(name)) {
                                        //member.getModifiers()获取成员变量 member 的修饰符值 可以序列化isTransient就为false
                                        isTransient = (member.getModifiers() & Opcodes.ACC_TRANSIENT) != 0;
                                        break;
                                    }
                                }
                                if (isTransient != null) {
                                    break;
                                }
                                // 向上父类遍历查找可被序列化字段
                                clazz = classMap.get(new ClassReference.Handle(clazz.getSuperClass()));
                            }
                        }
                        //污点列表
                        Set<Integer> taint;
                        if (!Boolean.TRUE.equals(isTransient)) {
                            //可以序列化
                            taint = getStackTaint(0);
                        } else {
                            //不可序列化
                            taint = new HashSet<>();
                        }
                        super.visitFieldInsn(opcode, owner, name, desc);
                        //设置栈顶是污点
                        setStackTaint(0, taint);
                        return;
                    }
                    break;
                case Opcodes.PUTFIELD:
                    break;
                default:
                    throw new IllegalStateException("Unsupported opcode: " + opcode);
            }

            super.visitFieldInsn(opcode, owner, name, desc);
        }

        @Override
        public void visitMethodInsn(int opcode, String owner, String name, String desc, boolean itf) {
//            todo 测试语句 使用 下面所有的在父类都已经实现 在这里 感觉没有太大的意义 直接使用super即可。测试无影响 做个记录 因为return Taint从栈里面获取
            super.visitMethodInsn(opcode, owner, name, desc, itf);
            //获取所有参数类型
//            Type[] argTypes = Type.getArgumentTypes(desc);
//
//            if (opcode != Opcodes.INVOKESTATIC) {
//                //创建一个原方法参数+1的数组
//                Type[] extendedArgTypes = new Type[argTypes.length+1];
//                //将argTypes 复制到extendedArgTypes 但是位置是从第一位开始  保留0
//                System.arraycopy(argTypes, 0, extendedArgTypes, 1, argTypes.length);
//                //将this 复制给第一位 因为是非静态方法
//                extendedArgTypes[0] = Type.getObjectType(owner);
//                // extendedArgTypes 赋值给原来的 argTypes 变量
//                argTypes = extendedArgTypes;
//            }
//            //返回方法类型的大小
//            int retSize = Type.getReturnType(desc).getSize();
//            Set<Integer> resultTaint;
//            switch (opcode) {
//                // 静态方法 调用实例 特殊方法调用 接口方法调用
//                case Opcodes.INVOKESTATIC:
//                case Opcodes.INVOKEVIRTUAL:
//                case Opcodes.INVOKESPECIAL:
//                case Opcodes.INVOKEINTERFACE:
//                    // 构造参数污染的集合 argTaint 创建空间大小
//                    final List<Set<Integer>> argTaint = new ArrayList<Set<Integer>>(argTypes.length);
//                    for (int i = 0; i < argTypes.length; i++) {
//                        argTaint.add(null);
//                    }
//
//                    int stackIndex = 0;
//                    for (int i = 0; i < argTypes.length; i++) {
//                        Type argType = argTypes[i];
//                        if (argType.getSize() > 0) {
//                            //argTaint参数污染  根据参数类型大小，从栈顶获取入参 参数入栈是从右到左的
//                            argTaint.set(argTypes.length - 1 - i, getStackTaint(stackIndex + argType.getSize() - 1));
//                        }
//                        //stack深度根据size增加
//                        stackIndex += argType.getSize();
//                    }
//
//                    if (name.equals("<init>")) {
//                        // Pass result taint through to original taint set; the initialized object is directly tainted by
//                        // parameters
//                        // 构造方法的调用，意味着参数0可以污染返回值 就将污点传递到原始污点集合中
//                        resultTaint = argTaint.get(0);
//                    } else {
//                        resultTaint = new HashSet<>();
//                    }
//                    //前面已经做了逆拓扑 调用链末端被先进行visit 因此前面方法已经被分析过了 也就是在这里方法返回值与哪个参数有关系，可能是空
//                    Set<Integer> passthrough = passthroughDataflow.get(new MethodReference.Handle(new ClassReference.Handle(owner), name, desc));
//                    if (passthrough != null) {
//                        for (Integer passthroughDataflowArg : passthrough) {
//                            //获取该参数的污点标记集合，并将其添加到结果集合 resultTaint中 以便存在返回结果  然后加入栈配合 下面retSize使用 看下面注释说明
//                            resultTaint.addAll(argTaint.get(passthroughDataflowArg));
//                        }
//                    }
//                    break;
//                default:
//                    throw new IllegalStateException("Unsupported opcode: " + opcode);
//            }
//
//            super.visitMethodInsn(opcode, owner, name, desc, itf);
//
//            if (retSize > 0) {
//                //如果被调用方法有返回值，那么调用方法体需要将方法返回时结果污点标记设置到返回值上,实现对返回值的污点追踪
//                //相当于stackVars.addAll(resultTaint) 也就是加载到栈上去 这里父类也有这一步  父类自己push到栈了  个人感觉重复了 先记下来
//                getStackTaint(retSize-1).addAll(resultTaint);
//            }
        }
    }


    public static void main(String[] args) throws Exception {
        ClassLoader classLoader = Util.getWarClassLoader(Paths.get(args[0]));

        PassthroughDiscovery passthroughDiscovery = new PassthroughDiscovery();
        passthroughDiscovery.discover(new ClassResourceEnumerator(classLoader), new JavaDeserializationConfig());
        passthroughDiscovery.save();
    }
}
