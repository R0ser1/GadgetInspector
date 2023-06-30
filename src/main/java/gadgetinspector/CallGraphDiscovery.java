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
import java.lang.reflect.Field;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class CallGraphDiscovery {
    private static final Logger LOGGER = LoggerFactory.getLogger(CallGraphDiscovery.class);

    private final Set<GraphCall> discoveredCalls = new HashSet<>();

    public void discover(final ClassResourceEnumerator classResourceEnumerator, GIConfig config) throws Exception {
        //把methods.dat 加载传递  其中key 为classReference name desc ||  value为前面说的加一个是否为静态方法
        Map<MethodReference.Handle, MethodReference> methodMap = DataLoader.loadMethods();
        //把classes.data 加载 key为class名 value为classReference 包括name superclass interface members【属性】
        Map<ClassReference.Handle, ClassReference> classMap = DataLoader.loadClasses();
        // 继承类 一个class 的父类和接口 然后使用InheritanceMap包装  其中包含inheritanceMap subClassMap 而后者是父类与子类的映射 key为父类  value是子类
        InheritanceMap inheritanceMap = InheritanceMap.load();
        //加载passthrough.dat key为classReference name desc || Value表示污染传递关系
        Map<MethodReference.Handle, Set<Integer>> passthroughDataflow = PassthroughDiscovery.load();
        // 序列化决策器 实际传入的也就inheritanceMap
        SerializableDecider serializableDecider = config.getSerializableDecider(methodMap, inheritanceMap);


        for (ClassResourceEnumerator.ClassResource classResource : classResourceEnumerator.getAllClasses()) {
            try (InputStream in = classResource.getInputStream()) {
                ClassReader cr = new ClassReader(in);
                try {
                    cr.accept(new ModelGeneratorClassVisitor(classMap, inheritanceMap, passthroughDataflow, serializableDecider, Opcodes.ASM9),
                            ClassReader.EXPAND_FRAMES);
                } catch (Exception e) {
                    LOGGER.error("Error analyzing: " + classResource.getName(), e);
                }
            }
        }
    }

    public void save() throws IOException {
        DataLoader.saveData(Paths.get("callgraph.dat"), new GraphCall.Factory(), discoveredCalls);
    }

    private class ModelGeneratorClassVisitor extends ClassVisitor {

        private final Map<ClassReference.Handle, ClassReference> classMap;
        private final InheritanceMap inheritanceMap;
        private final Map<MethodReference.Handle, Set<Integer>> passthroughDataflow;
        private final SerializableDecider serializableDecider;

        public ModelGeneratorClassVisitor(Map<ClassReference.Handle, ClassReference> classMap,
                                          InheritanceMap inheritanceMap,
                                          Map<MethodReference.Handle, Set<Integer>> passthroughDataflow,
                                          SerializableDecider serializableDecider, int api) {
            super(api);
            this.classMap = classMap;
            this.inheritanceMap = inheritanceMap;
            this.passthroughDataflow = passthroughDataflow;
            this.serializableDecider = serializableDecider;
        }

        private String name;
        private String signature;
        private String superName;
        private String[] interfaces;

        @Override
        public void visit(int version, int access, String name, String signature,
                          String superName, String[] interfaces) {
            super.visit(version, access, name, signature, superName, interfaces);
            this.name = name;
            this.signature = signature;
            this.superName = superName;
            this.interfaces = interfaces;
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String desc,
                                         String signature, String[] exceptions) {
            MethodVisitor mv = super.visitMethod(access, name, desc, signature, exceptions);
            ModelGeneratorMethodVisitor modelGeneratorMethodVisitor = new ModelGeneratorMethodVisitor(classMap,
                    inheritanceMap, passthroughDataflow, serializableDecider, api, mv, this.name, access, name, desc, signature, exceptions);

            return new JSRInlinerAdapter(modelGeneratorMethodVisitor, access, name, desc, signature, exceptions);
        }

        @Override
        public void visitOuterClass(String owner, String name, String desc) {
            // TODO: Write some tests to make sure we can ignore this
            super.visitOuterClass(owner, name, desc);
        }

        @Override
        public void visitInnerClass(String name, String outerName, String innerName, int access) {
            // TODO: Write some tests to make sure we can ignore this
            super.visitInnerClass(name, outerName, innerName, access);
        }

        @Override
        public void visitEnd() {
            super.visitEnd();
        }
    }

    private class ModelGeneratorMethodVisitor extends TaintTrackingMethodVisitor<String> {

        private final Map<ClassReference.Handle, ClassReference> classMap;
        private final InheritanceMap inheritanceMap;
        private final SerializableDecider serializableDecider;
        private final String owner;
        private final int access;
        private final String name;
        private final String desc;

        //todo: 解决数组问题 使用state transitions 这里解决的是引用类型
        protected int state;
        protected final static int SEEN_NOTHING = 0;
        protected static final int SEEN_ANEWARRAY= 1;
        protected static final int SEEN_DUP = 2;
        protected static final int SEEN_ICONST = 3;
        protected static final int SEEN_ALOAD = 4;
        protected static final int SEEN_AASTORE = 5;

        //下面解决是是byte等..
        private int state2;
        protected final static int SEEN2_NOTHING = 0;
        protected static final int SEEN2_NEWARRAY= 1;
        protected static final int SEEN2_DUP = 2;
        protected static final int SEEN2_ICONST = 3;
        protected static final int SEEN2_ILOAD = 4;
        protected static final int SEEN2_BASTORE = 5;

        //解决get
        private int state3;
        protected final static int SEEN3_NOTHING = 0;
        protected static final int SEEN3_ALOAD= 1;
        protected static final int SEEN3_Get= 2;

        //解决new 问题
        protected int state4;
        protected final static int SEEN4_NOTHING = 0;
        protected static final int SEEN4_NEW= 1;
        protected static final int SEEN4_DUP = 2;
        protected static final int SEEN4_ALOAD = 3;
        protected static final int SEEN4_ASTORE = 4;

        public ModelGeneratorMethodVisitor(Map<ClassReference.Handle, ClassReference> classMap,
                                           InheritanceMap inheritanceMap,
                                           Map<MethodReference.Handle, Set<Integer>> passthroughDataflow,
                                           SerializableDecider serializableDecider, final int api, final MethodVisitor mv,
                                           final String owner, int access, String name, String desc, String signature,
                                           String[] exceptions) {
            super(inheritanceMap, passthroughDataflow, api, mv, owner, access, name, desc, signature, exceptions);
            this.classMap = classMap;
            this.inheritanceMap = inheritanceMap;
            this.serializableDecider = serializableDecider;
            this.owner = owner;
            this.access = access;
            this.name = name;
            this.desc = desc;
        }

        @Override
        public void visitCode() {
            super.visitCode();

            int localIndex = 0;
            int argIndex = 0;
            //todo 测试  这里是静态方法的话从1
            if ((this.access & Opcodes.ACC_STATIC) != 0){
                argIndex=1;
            }
            //非静态方法
            if ((this.access & Opcodes.ACC_STATIC) == 0) {
                setLocalTaint(localIndex, "arg" + argIndex);
                localIndex += 1;
                argIndex += 1;
            }
            for (Type argType : Type.getArgumentTypes(desc)) {
                setLocalTaint(localIndex, "arg" + argIndex);
                localIndex += argType.getSize();
                argIndex += 1;
            }
        }



        @Override
        public void visitInsn(int opcode) {
            switch (opcode){
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
            }

            super.visitInsn(opcode);
        }

        @Override
        public void visitVarInsn(int opcode, int var) {
            super.visitVarInsn(opcode, var);
            //todo 这里是最后一步 所以必须等aload之后再 给栈污点
            if (opcode==Opcodes.ALOAD&&state==SEEN_ICONST){
                state=SEEN_ALOAD;
            }
            if (opcode==Opcodes.ILOAD&&state2==SEEN2_ICONST){
                state2=SEEN2_ILOAD;
            }
            if (opcode==Opcodes.ALOAD){
                state3=SEEN3_ALOAD;
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
        public void visitFieldInsn(int opcode, String owner, String name, String desc) {

            switch (opcode) {
                case Opcodes.GETSTATIC:
                    break;
                case Opcodes.PUTSTATIC:
                    break;
                case Opcodes.GETFIELD:
                    Type type = Type.getType(desc);
                    if (type.getSize() == 1) {
                        Boolean isTransient = null;

                        // If a field type could not possibly be serialized, it's effectively transient
                        if (!couldBeSerialized(serializableDecider, inheritanceMap, new ClassReference.Handle(type.getInternalName()))) {
                            isTransient = Boolean.TRUE;
                        } else {
                            ClassReference clazz = classMap.get(new ClassReference.Handle(owner));
                            while (clazz != null) {
                                for (ClassReference.Member member : clazz.getMembers()) {
                                    if (member.getName().equals(name)) {
                                        isTransient = (member.getModifiers() & Opcodes.ACC_TRANSIENT) != 0;
                                        break;
                                    }
                                }
                                if (isTransient != null) {
                                    break;
                                }
                                clazz = classMap.get(new ClassReference.Handle(clazz.getSuperClass()));
                            }
                        }

                        Set<String> newTaint = new HashSet<>();
                        if (!Boolean.TRUE.equals(isTransient)) {
                            //通过决策器 则将栈顶元素arg0(类实例) 结合属性 添加到newTaint
                            for (String s : getStackTaint(0)) {
                                newTaint.add(s + "." + name);
                            }
                        }
                        super.visitFieldInsn(opcode, owner, name, desc);
                        setStackTaint(0, newTaint);
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

        // todo 处理最简单的Lambda表达式[显式的].且可能是有问题的.
        @Override
        public void visitInvokeDynamicInsn(String name, String desc, Handle bsm, Object... bsmArgs) {
            if (bsm.getOwner().equals("java/lang/invoke/LambdaMetafactory")){
                //获取调用的类名
                String callerowner = Type.getReturnType(desc).getInternalName();
                //获取调用的方法
                String callername=name;
                //获取调用方法的描述符 其实这里直接使用的是Lambda表达式实现的函数接口类型 并没有使用获取desc
                // 有点问题因为 这里默认是调用的这个 函数接口
                String callerdescriptor = Type.getObjectType(((Type) (bsmArgs[0])).getDescriptor()).getInternalName();
                //获取调用参数个数
                int srcArgIndex = Type.getArgumentTypes(callerdescriptor).length;
//====================================================================================================//
                //获取待调用的类
                String targetowner = Type.getObjectType(((Handle) bsmArgs[1]).getOwner()).getInternalName();
                //获取待调用的方法n
                String targetname = Type.getObjectType(((Handle) bsmArgs[1]).getName()).getInternalName();
                //获取待调用的方法描述符
                String targetdesc = Type.getObjectType(((Handle) bsmArgs[1]).getDesc()).getInternalName();
                //获取被调用参数个数
                int argIndex = Type.getArgumentTypes(targetdesc).length;
//====================================================================================================//
////                判断Runnable.run()函数接口 //测试 不一定有用
//                if (callername.equals("run")&&desc.equals("(Ljava/lang/Object;)Ljava/lang/Runnable;")){
//                    discoveredCalls.add(new GraphCall(
//                            //这里是实际上操作的类[调用者] 以及类的方法  方法的描述符
//                            new MethodReference.Handle(new ClassReference.Handle(this.owner), this.name, this.desc),
//                            //这是操作类中调用的类[被调用者] 以及调用类的方法  以及调用类方法的描述符
//                            new MethodReference.Handle(new ClassReference.Handle(callerowner), callername, callerdescriptor),
//                            //调用方法的参数索引
//                            argIndex,
//                            //调用者类的 属性
//                            null,
//                            //被调用者方法的参数索引
//                            srcArgIndex));
//                }
//====================================================================================================//
                discoveredCalls.add(new GraphCall(
                        //这里是实际上操作的类[调用者] 以及类的方法  方法的描述符
                        new MethodReference.Handle(new ClassReference.Handle(callerowner), callername, callerdescriptor),
                        //这是操作类中调用的类[被调用者] 以及调用类的方法  以及调用类方法的描述符
                        new MethodReference.Handle(new ClassReference.Handle(targetowner), targetname, targetdesc),
                        //调用方法的参数索引
                        srcArgIndex,
                        //调用者类的 属性
                        null,
                        //被调用者方法的参数索引
                        argIndex));
            }

            // 调用父类方法
            super.visitInvokeDynamicInsn(name, desc, bsm, bsmArgs);
        }



        @Override
        public void visitMethodInsn(int opcode, String owner, String name, String desc, boolean itf) {
            //获取被调用对象所有参数类型
            Type[] argTypes = Type.getArgumentTypes(desc);
            if (opcode != Opcodes.INVOKESTATIC) {
                //创建一个原方法参数+1的数组
                Type[] extendedArgTypes = new Type[argTypes.length+1];
                //将argTypes 复制到extendedArgTypes 但是位置是从第一位开始  保留0
                System.arraycopy(argTypes, 0, extendedArgTypes, 1, argTypes.length);
                //将this 复制给第一位 因为是非静态方法
                extendedArgTypes[0] = Type.getObjectType(owner);
                // extendedArgTypes 赋值给原来的 argTypes 变量
                argTypes = extendedArgTypes;
            }

            switch (opcode) {
                case Opcodes.INVOKESTATIC:
                case Opcodes.INVOKEVIRTUAL:
                case Opcodes.INVOKESPECIAL:
                case Opcodes.INVOKEINTERFACE:
                    int stackIndex = 0;
                    for (int i = 0; i < argTypes.length; i++) {
                        //从栈顶获取 被调用方法的参数索引
                        int argIndex = argTypes.length-1-i;
                        Type type = argTypes[argIndex];
                        //从栈顶获取调用者的参数 也就是污点 因为提前入栈过了 从左到右
                        Set<String> taint = getStackTaint(stackIndex);
                        if (taint.size() > 0) {
                            //todo 处理spring model中的get 设置污点传递 挺有局限性的
                            if (argTypes.length == 1 && name.startsWith("get")&&state3==SEEN3_ALOAD){
                                visitVar_get();
                                state3=SEEN3_NOTHING;
                            }
                            for (String argSrc : taint) {
//                            if (!argSrc.substring(0, 3).equals("arg")) {
//                                throw new IllegalStateException("Invalid taint arg: " + argSrc);
//                            }
                                //根据代码解析从污点信息中提取出来的源参数索引
                                int dotIndex = argSrc.indexOf('.');
                                //调用方法的参数索引
                                int srcArgIndex;
                                String srcArgPath;
                                if (dotIndex == -1) {
                                    //如果污点信息中只含有一个整数 则将这个整数解析为源参数索引
                                    //拿到字符串中的数字 arg1 即1
                                    srcArgIndex = Integer.parseInt(argSrc.substring(3));
                                    srcArgPath = null;
                                } else {
                                        //否则将字符串按照点号分割成两部分，第一部分表示源参数索引 也就是栈的第几个元素，第二部分表示调用者的属性名。通常为一个对象的时候 例如arg0.name、arg0.age
                                    srcArgIndex = Integer.parseInt(argSrc.substring(3, dotIndex));
                                    srcArgPath = argSrc.substring(dotIndex + 1);
                                }
                                //todo 这里是为了处理静态方法  参数问题+1
                                if (opcode == Opcodes.INVOKESTATIC){
                                    discoveredCalls.add(new GraphCall(
                                            //这里是实际上操作的类[调用者] 以及类的方法  方法的描述符
                                            new MethodReference.Handle(new ClassReference.Handle(this.owner), this.name, this.desc),
                                            //这是操作类中调用的类[被调用者] 以及调用类的方法  以及调用类方法的描述符
                                            new MethodReference.Handle(new ClassReference.Handle(owner), name, desc),
                                            //调用方法的参数索引
                                            srcArgIndex,
                                            //调用者类的 属性
                                            srcArgPath,
                                            //被调用者方法的参数索引
                                            argIndex+1));
                                }else {
                                    discoveredCalls.add(new GraphCall(
                                            //这里是实际上操作的类[调用者] 以及类的方法  方法的描述符
                                            new MethodReference.Handle(new ClassReference.Handle(this.owner), this.name, this.desc),
                                            //这是操作类中调用的类[被调用者] 以及调用类的方法  以及调用类方法的描述符
                                            new MethodReference.Handle(new ClassReference.Handle(owner), name, desc),
                                            //调用方法的参数索引
                                            srcArgIndex,
                                            //调用者类的 属性
                                            srcArgPath,
                                            //被调用者方法的参数索引
                                            argIndex));
                                }
                            }
                        }

                        stackIndex += type.getSize();
                    }
                    break;
                default:
                    throw new IllegalStateException("Unsupported opcode: " + opcode);
            }

            super.visitMethodInsn(opcode, owner, name, desc, itf);
        }
    }

    public static void main(String[] args) throws Exception {
        ClassLoader classLoader = Util.getWarClassLoader(Paths.get(args[0]));

        CallGraphDiscovery callGraphDiscovery = new CallGraphDiscovery();
        callGraphDiscovery.discover(new ClassResourceEnumerator(classLoader), new JavaDeserializationConfig());
        callGraphDiscovery.save();
    }
}
