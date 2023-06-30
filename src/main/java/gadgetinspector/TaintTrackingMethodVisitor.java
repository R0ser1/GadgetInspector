package gadgetinspector;

import gadgetinspector.data.ClassReference;
import gadgetinspector.data.InheritanceMap;
import gadgetinspector.data.MethodReference;
import org.objectweb.asm.*;
import org.objectweb.asm.commons.AnalyzerAdapter;

import java.util.*;

public class TaintTrackingMethodVisitor<T> extends MethodVisitor {
    //测试
    private static boolean flag=false;
    private static final Object[][] PASSTHROUGH_DATAFLOW = new Object[][] {
            { "java/lang/Object", "toString", "()Ljava/lang/String;", 0 },

            // Taint from ObjectInputStream. Note that defaultReadObject() is handled differently below
            { "java/io/ObjectInputStream", "readObject", "()Ljava/lang/Object;", 0},
            { "java/io/ObjectInputStream", "readFields", "()Ljava/io/ObjectInputStream$GetField;", 0},
            { "java/io/ObjectInputStream$GetField", "get", "(Ljava/lang/String;Ljava/lang/Object;)Ljava/lang/Object;", 0 },

            // Pass taint from class name to returned class
            { "java/lang/Object", "getClass", "()Ljava/lang/Class;", 0 },
            { "java/lang/Class", "forName", "(Ljava/lang/String;)Ljava/lang/Class;", 0 },
            // Pass taint from class or method name to returned method
            { "java/lang/Class", "getMethod", "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;", 0, 1 },
            // Pass taint from class to methods
            { "java/lang/Class", "getMethods", "()[Ljava/lang/reflect/Method;", 0 },

            { "java/lang/StringBuilder", "<init>", "(Ljava/lang/String;)V", 0, 1 },
            { "java/lang/StringBuilder", "<init>", "(Ljava/lang/CharSequence;)V", 0, 1 },
            { "java/lang/StringBuilder", "append", "(Ljava/lang/Object;)Ljava/lang/StringBuilder;", 0, 1 },
            { "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", 0, 1 },
            { "java/lang/StringBuilder", "append", "(Ljava/lang/StringBuffer;)Ljava/lang/StringBuilder;", 0, 1 },
            { "java/lang/StringBuilder", "append", "(Ljava/lang/CharSequence;)Ljava/lang/StringBuilder;", 0, 1 },
            { "java/lang/StringBuilder", "append", "(Ljava/lang/CharSequence;II)Ljava/lang/StringBuilder;", 0, 1 },
            { "java/lang/StringBuilder", "toString", "()Ljava/lang/String;", 0 },

            { "java/io/ByteArrayInputStream", "<init>", "([B)V", 1 },
            { "java/io/ByteArrayInputStream", "<init>", "([BII)V", 1 },
            { "java/io/ObjectInputStream", "<init>", "(Ljava/io/InputStream;)V", 1},
            { "java/io/File", "<init>", "(Ljava/lang/String;I)V", 1},
            { "java/io/File", "<init>", "(Ljava/lang/String;Ljava/io/File;)V", 1},
            { "java/io/File", "<init>", "(Ljava/lang/String;)V", 1},
            { "java/io/File", "<init>", "(Ljava/lang/String;Ljava/lang/String;)V", 1},
            { "java/nio/paths/Paths", "get", "(Ljava/lang/String;[Ljava/lang/String;)Ljava/nio/file/Path;", 0},

            { "java/net/URL", "<init>", "(Ljava/lang/String;)V", 1 },
            //添加白名单 类型转换
            {"java/lang/String","replace","(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Ljava/lang/String;",0},
            {"java/lang/String","valueOf","(Ljava/lang/Object;)Ljava/lang/String;",0},
            {"java/lang/String","getBytes","()[B",0},
            {"java/util/Base64$Decoder","decode","(Ljava/lang/String;)[B",0},
            {"java/util/Base64$Decoder","decode","([B)[B",0},
            {"java/lang/String","format","(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;",0,1},
            //其他师傅 为验证 没看懂Method invoke干嘛的 未测试····
            {"java/lang/Class", "getDeclaredMethod", "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;", 0, 1},
            {"java/lang/Class", "getDeclaredMethods", "()[Ljava/lang/reflect/Method;", 0},
            {"java/lang/Class", "getDeclaredConstructors", "()[Ljava/lang/reflect/Constructor;", 0},
            {"java/lang/Class", "getDeclaredConstructor", "[Ljava/lang/Class;)Ljava/lang/reflect/Constructor;", 0, 1},
            {"java/lang/Class", "getConstructor", "([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;", 0, 1},
            {"java/lang/Class", "getConstructors", "()[Ljava/lang/reflect/Constructor;", 0},
            {"java/util/List", "add", "(Ljava/lang/Object;)Z", 0,1},
            {"java/lang/reflect/Constructor", "newInstance", "([Ljava/lang/Object;)Ljava/lang/Object;", 0, 1},
            {"java/lang/reflect/Method", "invoke", "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", 0, 1, 2},
            {"java/lang/Process", "getInputStream", "()Ljava/io/InputStream;", 0},
            {"java/util/Scanner", "<init>", "(Ljava/io/InputStream;)V", 1},
            {"java/util/Scanner", "next", "()Ljava/lang/String;", 0},
            {"java/io/BufferedReader", "readLine", "()Ljava/lang/String;", 0},
            //添加* 未测试····
            {"java/lang/String", "substring", "*", 0},
            {"java/lang/String", "getBytes", "*", 0},
            {"sun/misc/BASE64Encoder", "encode", "*", 1},
            {"sun/misc/BASE64Decoder", "decodeBuffer", "*", 1},
            {"sun/misc/BASE64Decoder", "decodeBufferToByteBuffer", "*", 1},
            {"java/util/Base64$Decoder", "decode", "*", 1},
            //获取参数
            {"javax/servlet/http/HttpServletRequest","getCookies","*",0},
            {"javax/servlet/http/Cookie","getValue","*",0},
            { "javax/servlet/http/HttpServletRequest", "getParameter", "(Ljava/lang/String;)Ljava/lang/String;", 0 },
            { "javax/servlet/http/HttpServletRequest", "getQueryString", "()Ljava/lang/String;", 0 },
            { "javax/servlet/http/HttpServletRequest", "getParameterNames", "()Ljava/util/Enumeration;", 0 },
            { "javax/servlet/http/HttpServletRequest", "getParameterValues", "(Ljava/lang/String;)[Ljava/lang/String;", 0 },
            { "javax/servlet/http/HttpServletRequest", "getParameterMap", "()Ljava/util/Map;", 0 },
            { "javax/servlet/http/HttpServletRequest", "getHeader", "(Ljava/lang/String;)Ljava/lang/String;", 0 },
            { "javax/servlet/http/HttpServletRequest", "getHeaders", "(Ljava/lang/String;)Ljava/util/Enumeration;", 0 },
            { "javax/servlet/http/HttpServletRequest", "getHeaderNames", "()Ljava/util/Enumeration;", 0 },
            { "org/springframework/jdbc/core/JdbcTemplate$1QueryStatementCallback", "<init>", "(Lorg/springframework/jdbc/core/JdbcTemplate;Ljava/lang/String;Lorg/springframework/jdbc/core/ResultSetExtractor;)V", 2 },



    };

    public static class SavedVariableState<T> {
        List<Set<T>> localVars;
        List<Set<T>> stackVars;

        public SavedVariableState() {
            localVars = new ArrayList<>();
            stackVars = new ArrayList<>();
        }
        public SavedVariableState(SavedVariableState<T> copy) {
            this.localVars = new ArrayList<>(copy.localVars.size());
            this.stackVars = new ArrayList<>(copy.stackVars.size());

            for (Set<T> original : copy.localVars) {
                this.localVars.add(new HashSet<>(original));
            }
            for (Set<T> original : copy.stackVars) {
                this.stackVars.add(new HashSet<>(original));
            }
        }

        public void combine(SavedVariableState<T> copy) {
            for (int i = 0; i < copy.localVars.size(); i++) {
                while (i >= this.localVars.size()) {
                    this.localVars.add(new HashSet<T>());
                }
                this.localVars.get(i).addAll(copy.localVars.get(i));
            }
            for (int i = 0; i < copy.stackVars.size(); i++) {
                while (i >= this.stackVars.size()) {
                    this.stackVars.add(new HashSet<T>());
                }
                this.stackVars.get(i).addAll(copy.stackVars.get(i));
            }
        }
    }

    private final InheritanceMap inheritanceMap;
    private final Map<MethodReference.Handle, Set<Integer>> passthroughDataflow;

    private final AnalyzerAdapter analyzerAdapter;
    private final int access;
    private final String name;
    private final String desc;
    private final String signature;
    private final String[] exceptions;

    public TaintTrackingMethodVisitor(InheritanceMap inheritanceMap,
                                      Map<MethodReference.Handle, Set<Integer>> passthroughDataflow,
                                      final int api, final MethodVisitor mv, final String owner, int access,
                                      String name, String desc, String signature, String[] exceptions) {
        super(api, new AnalyzerAdapter(owner, access, name, desc, mv));
        this.inheritanceMap = inheritanceMap;
        this.passthroughDataflow = passthroughDataflow;
        this.analyzerAdapter = (AnalyzerAdapter)this.mv;
        this.access = access;
        this.name = name;
        this.desc = desc;
        this.signature = signature;
        this.exceptions = exceptions;
    }

    private SavedVariableState<T> savedVariableState = new SavedVariableState<T>();
    private Map<Label, SavedVariableState<T>> gotoStates = new HashMap<Label, SavedVariableState<T>>();
    private Set<Label> exceptionHandlerLabels = new HashSet<Label>();

    @Override
    public void visitCode() {
        super.visitCode();
        savedVariableState.localVars.clear();
        savedVariableState.stackVars.clear();

        if ((this.access & Opcodes.ACC_STATIC) == 0) {
            // 如果非static 那么 直接占位1 因为非静态方法默认是存储this的
            savedVariableState.localVars.add(new HashSet<T>());
        }
        for (Type argType : Type.getArgumentTypes(desc)) {
            for (int i = 0; i < argType.getSize(); i++) {
                // 根据arg size 将所有的参数都占位处理
                savedVariableState.localVars.add(new HashSet<T>());
            }
        }
    }

    private void push(T ... possibleValues) {
        Set<T> vars = new HashSet<>();
        for (T s : possibleValues) {
            vars.add(s);
        }
        savedVariableState.stackVars.add(vars);
    }
    private void push(Set<T> possibleValues) {
        // Intentionally make this a reference to the same set
        savedVariableState.stackVars.add(possibleValues);
    }
    private Set<T> pop() {
        //stack后入先出，所以是栈顶元素
        return savedVariableState.stackVars.remove(savedVariableState.stackVars.size()-1);
    }
    private Set<T> get(int stackIndex) {
        return savedVariableState.stackVars.get(savedVariableState.stackVars.size()-1-stackIndex);
    }

    @Override
    public void visitFrame(int type, int nLocal, Object[] local, int nStack, Object[] stack) {
        if (type != Opcodes.F_NEW) {
            throw new IllegalStateException("Compressed frame encountered; class reader should use accept() with EXPANDED_FRAMES option.");
        }
        int stackSize = 0;
        for (int i = 0; i < nStack; i++) {
            Object typ = stack[i];
            int objectSize = 1;
            if (typ.equals(Opcodes.LONG) || typ.equals(Opcodes.DOUBLE)) {
                objectSize = 2;
            }
            for (int j = savedVariableState.stackVars.size(); j < stackSize+objectSize; j++) {
                savedVariableState.stackVars.add(new HashSet<T>());
            }
            stackSize += objectSize;
        }
        int localSize = 0;
        for (int i = 0; i < nLocal; i++) {
            Object typ = local[i];
            int objectSize = 1;
            if (typ.equals(Opcodes.LONG) || typ.equals(Opcodes.DOUBLE)) {
                objectSize = 2;
            }
            for (int j = savedVariableState.localVars.size(); j < localSize+objectSize; j++) {
                savedVariableState.localVars.add(new HashSet<T>());
            }
            localSize += objectSize;
        }
        for (int i = savedVariableState.stackVars.size() - stackSize; i > 0; i--) {
            savedVariableState.stackVars.remove(savedVariableState.stackVars.size()-1);
        }
        for (int i = savedVariableState.localVars.size() - localSize; i > 0; i--) {
            savedVariableState.localVars.remove(savedVariableState.localVars.size()-1);
        }

        super.visitFrame(type, nLocal, local, nStack, stack);

        sanityCheck();
    }
    //todo 获取aload到栈上的元素 也就是参数 污点~~~ 然后因为astore 需要pop三次 所以减掉4  前面一位设置污点 以及防止误报 当前栈需要大于4
    public void visitInsn_array(int state){
        if (state==4&&savedVariableState.stackVars.size()>=4){
            savedVariableState.stackVars.set(savedVariableState.stackVars.size()-4,savedVariableState.stackVars.get(savedVariableState.stackVars.size()-1));
        }
    }
    //todo 设置栈顶元素为arg1 也就是污点 因为很有局限性..........
    public void visitVar_get() {
        if (savedVariableState.stackVars.size()>0&&savedVariableState.localVars.size()>1) {
            flag=true;
        }
    }
    //todo 测试new 存在误报...... 没办法啦~
    public void visitVar_new(int state) {
        if (state==3&&savedVariableState.stackVars.size()>=3){
            savedVariableState.stackVars.set(savedVariableState.stackVars.size()-3,savedVariableState.stackVars.get(savedVariableState.stackVars.size()-1));
        }
    }
//指令操作 集合 注释了部分 自行实现模拟了JVM整个部分 指令太多了 只需要了解一些即可
//可以再官网自行查看 含义 https://docs.oracle.com/javase/specs/jvms/se7/html/jvms-6.html#jvms-6.5.baload
    @Override
    public void visitInsn(int opcode) {
        Set<T> saved0, saved1, saved2, saved3;
        sanityCheck();

        switch(opcode) {
            case Opcodes.NOP:
                break;
            case Opcodes.ACONST_NULL:
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
                //将不同的常量压入栈 指向push
                push();
                break;
            case Opcodes.LCONST_0:
            case Opcodes.LCONST_1:
            case Opcodes.DCONST_0:
            case Opcodes.DCONST_1:
                //size为2需要两次push
                push();
                push();
                break;
            case Opcodes.IALOAD:
            case Opcodes.FALOAD:
            case Opcodes.AALOAD:
            case Opcodes.BALOAD:
            case Opcodes.CALOAD:
            case Opcodes.SALOAD:
                //这些指令都是数组 第一次pop 弹出数组的引用，第二次pop 弹出数组索引
                // push是将value压入栈
                pop();
                pop();
                // todo 直接把数组当为 污点 没有细分 是第几个
                if (savedVariableState.localVars.size()>1){
                    push(savedVariableState.localVars.get(savedVariableState.localVars.size()-1));
                }else {
                    push();
                }
                break;
            case Opcodes.LALOAD:
            case Opcodes.DALOAD:
                // 同理sizi 2所以push两次
                pop();
                pop();
                push();
                push();
                break;
            case Opcodes.IASTORE:
            case Opcodes.FASTORE:
            case Opcodes.AASTORE:
            case Opcodes.BASTORE:
            case Opcodes.CASTORE:
            case Opcodes.SASTORE:
                //pop 存储的元素的值
                //pop 操作数是数组引用
                //pop 存储的元素索引
                pop();
                pop();
                pop();
                break;
            case Opcodes.LASTORE:
            case Opcodes.DASTORE:
                //同上 size 2
                pop();
                pop();
                pop();
                pop();
                break;
            case Opcodes.POP:
                pop();
                break;
            case Opcodes.POP2:
                pop();
                pop();
                break;
            case Opcodes.DUP:
                push(get(0));
                break;
            case Opcodes.DUP_X1:
                saved0 = pop();
                saved1 = pop();
                push(saved0);
                push(saved1);
                push(saved0);
                break;
            case Opcodes.DUP_X2:
                saved0 = pop(); // a
                saved1 = pop(); // b
                saved2 = pop(); // c
                push(saved0); // a
                push(saved2); // c
                push(saved1); // b
                push(saved0); // a
                break;
            case Opcodes.DUP2:
                // a b
                push(get(1)); // a b a
                push(get(1)); // a b a b
                break;
            case Opcodes.DUP2_X1:
                // a b c
                saved0 = pop();
                saved1 = pop();
                saved2 = pop();
                push(saved1); // b
                push(saved0); // c
                push(saved2); // a
                push(saved1); // b
                push(saved0); // c
                break;
            case Opcodes.DUP2_X2:
                // a b c d
                saved0 = pop();
                saved1 = pop();
                saved2 = pop();
                saved3 = pop();
                push(saved1); // c
                push(saved0); // d
                push(saved3); // a
                push(saved2); // b
                push(saved1); // c
                push(saved0); // d
                break;
            case Opcodes.SWAP:
                saved0 = pop();
                saved1 = pop();
                push(saved0);
                push(saved1);
                break;
            case Opcodes.IADD:
            case Opcodes.FADD:
            case Opcodes.ISUB:
            case Opcodes.FSUB:
            case Opcodes.IMUL:
            case Opcodes.FMUL:
            case Opcodes.IDIV:
            case Opcodes.FDIV:
            case Opcodes.IREM:
            case Opcodes.FREM:
                pop();
                pop();
                push();
                break;
            case Opcodes.LADD:
            case Opcodes.DADD:
            case Opcodes.LSUB:
            case Opcodes.DSUB:
            case Opcodes.LMUL:
            case Opcodes.DMUL:
            case Opcodes.LDIV:
            case Opcodes.DDIV:
            case Opcodes.LREM:
            case Opcodes.DREM:
                pop();
                pop();
                pop();
                pop();
                push();
                push();
                break;
            case Opcodes.INEG:
            case Opcodes.FNEG:
                pop();
                push();
                break;
            case Opcodes.LNEG:
            case Opcodes.DNEG:
                pop();
                pop();
                push();
                push();
                break;
            case Opcodes.ISHL:
            case Opcodes.ISHR:
            case Opcodes.IUSHR:
                pop();
                pop();
                push();
                break;
            case Opcodes.LSHL:
            case Opcodes.LSHR:
            case Opcodes.LUSHR:
                pop();
                pop();
                pop();
                push();
                push();
                break;
            case Opcodes.IAND:
            case Opcodes.IOR:
            case Opcodes.IXOR:
                pop();
                pop();
                push();
                break;
            case Opcodes.LAND:
            case Opcodes.LOR:
            case Opcodes.LXOR:
                pop();
                pop();
                pop();
                pop();
                push();
                push();
                break;
            case Opcodes.I2B:
            case Opcodes.I2C:
            case Opcodes.I2S:
            case Opcodes.I2F:
                pop();
                push();
                break;
            case Opcodes.I2L:
            case Opcodes.I2D:
                pop();
                push();
                push();
                break;
            case Opcodes.L2I:
            case Opcodes.L2F:
                pop();
                pop();
                push();
                break;
            case Opcodes.D2L:
            case Opcodes.L2D:
                pop();
                pop();
                push();
                push();
                break;
            case Opcodes.F2I:
                pop();
                push();
                break;
            case Opcodes.F2L:
            case Opcodes.F2D:
                pop();
                push();
                push();
                break;
            case Opcodes.D2I:
            case Opcodes.D2F:
                pop();
                pop();
                push();
                break;
            case Opcodes.LCMP:
                pop();
                pop();
                pop();
                pop();
                push();
                break;
            case Opcodes.FCMPL:
            case Opcodes.FCMPG:
                pop();
                pop();
                push();
                break;
            case Opcodes.DCMPL:
            case Opcodes.DCMPG:
                pop();
                pop();
                pop();
                pop();
                push();
                break;
            case Opcodes.IRETURN:
            case Opcodes.FRETURN:
            case Opcodes.ARETURN:
                //指令用于将栈顶的值出栈 因为我们刚刚push 将指加载到了栈顶上
                pop();
                break;
            case Opcodes.LRETURN:
            case Opcodes.DRETURN:
                // size 2
                pop();
                pop();
                break;
            case Opcodes.RETURN:
                break;
            case Opcodes.ARRAYLENGTH:
                pop();
                push();
                break;
            case Opcodes.ATHROW:
                pop();
                break;
            case Opcodes.MONITORENTER:
            case Opcodes.MONITOREXIT:
                pop();
                break;
            default:
                throw new IllegalStateException("Unsupported opcode: " + opcode);
        }

        super.visitInsn(opcode);

        sanityCheck();
    }
//int操作数指令
    @Override
    public void visitIntInsn(int opcode, int operand) {
        switch(opcode) {
            case Opcodes.BIPUSH:
            case Opcodes.SIPUSH:
                //push一个值
                push();
                break;
            case Opcodes.NEWARRAY:
                //从操作树栈 弹出一个整数 表示要创建的数组长度，并将一个新的 int 类型数组对象压入操作数栈中
                pop();
                push();
                break;
            default:
                throw new IllegalStateException("Unsupported opcode: " + opcode);
        }

        super.visitIntInsn(opcode, operand);

        sanityCheck();
    }
// 用于访问局部变量的指令 提供了对这些局部变量操作的访问，包括读取、修改、装载和存储等指令
    @Override
    public void visitVarInsn(int opcode, int var) {
        // 该循环将在本地变量状态中添加缺失的变量污点信息集合，以确保该状态正确地表示函数中所有的本地变量。 例如 方法中出现 ASTORE,2 将一个值从操作数栈中弹出并存储到本地变量中
        for (int i = savedVariableState.localVars.size(); i <= var; i++) {
            savedVariableState.localVars.add(new HashSet<T>());
        }

        Set<T> saved0;
        switch(opcode) {
            case Opcodes.ILOAD:
            case Opcodes.FLOAD:
                //加载到栈顶
                push();
                break;
            case Opcodes.LLOAD:
            case Opcodes.DLOAD:
                //size 2
                push();
                push();
                break;
            case Opcodes.ALOAD:
                // ALOAD代表将局部变量加载到操作树栈 所以这里从loaclvars 获取引用 将方法的参数加载上去
                push(savedVariableState.localVars.get(var));
                break;
            case Opcodes.ISTORE:
            case Opcodes.FSTORE:
                //储存到局部变量中 所以pop掉栈顶的value
                pop();
                //设置到localvars上来
                savedVariableState.localVars.set(var, new HashSet<T>());
                break;
            case Opcodes.DSTORE:
            case Opcodes.LSTORE:
                //size 2
                pop();
                pop();
                savedVariableState.localVars.set(var, new HashSet<T>());
                break;
            case Opcodes.ASTORE:
                // 用于将对象引用存储到局部变量表中的指令 所以先弹出  使用变量存储进去
                saved0 = pop();
                savedVariableState.localVars.set(var, saved0);
                break;
            case Opcodes.RET:
                // No effect on stack
                break;
            default:
                throw new IllegalStateException("Unsupported opcode: " + opcode);
        }

        super.visitVarInsn(opcode, var);

        sanityCheck();
    }

    @Override
    public void visitTypeInsn(int opcode, String type) {
        switch(opcode) {
            case Opcodes.NEW:
                // 创建了对象并将其引用推入操作数栈中
                push();
                break;
            case Opcodes.ANEWARRAY:
                //操作数栈中弹出一个size大小的整数，表示要创建的数组长度 然后将对象压入操作树栈中 因为使用ANEWARRAY之前需要先创建数组长度来压入操作树栈中
                pop();
                push();
                break;
            case Opcodes.CHECKCAST:
                // No-op
                break;
            case Opcodes.INSTANCEOF:
                //操作数栈中弹出一个对象引用，并将其转换成要检查的类型。如果该对象是该类型或其子类/实现类的实例. 然后根据不同的需求 来压入栈
                pop();
                push();
                break;
            default:
                throw new IllegalStateException("Unsupported opcode: " + opcode);
        }

        super.visitTypeInsn(opcode, type);

        sanityCheck();
    }

    @Override
    public void visitFieldInsn(int opcode, String owner, String name, String desc) {
        //获取段类型所需的操作数栈大小 根据不同的指令来压入typeSize大小 或着 弹出typeSize大小
        //主要是GETSTATIC 和 PUTSTATIC 操作码是针对静态字段的，而 GETFIELD 和 PUTFIELD 操作码是针对实例字段的
        int typeSize = Type.getType(desc).getSize();
        switch (opcode) {
            case Opcodes.GETSTATIC:
                for (int i = 0; i < typeSize; i++) {
                    push();
                }
                break;
            case Opcodes.PUTSTATIC:
                for (int i = 0; i < typeSize; i++) {
                    pop();
                }
                break;
            case Opcodes.GETFIELD:
                //弹出对象引用 再压入typeSize
                pop();
                for (int i = 0; i < typeSize; i++) {
                    push();
                }
                break;
            case Opcodes.PUTFIELD:
                // 弹出对象引用 以及自身typesize个值
                for (int i = 0; i < typeSize; i++) {
                    pop();
                }
                pop();

                break;
            default:
                throw new IllegalStateException("Unsupported opcode: " + opcode);
        }

        super.visitFieldInsn(opcode, owner, name, desc);

        sanityCheck();
    }

    @Override
    public void visitMethodInsn(int opcode, String owner, String name, String desc, boolean itf) {
        final MethodReference.Handle methodHandle = new MethodReference.Handle(
                new ClassReference.Handle(owner), name, desc);
        //获取所有参数类型
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
        // 获取方法返回的类型 以及 大小
        final Type returnType = Type.getReturnType(desc);
        final int retSize = returnType.getSize();

        switch (opcode) {
            // 静态方法 调用实例 特殊方法调用 接口方法调用
            case Opcodes.INVOKESTATIC:
            case Opcodes.INVOKEVIRTUAL:
            case Opcodes.INVOKESPECIAL:
            case Opcodes.INVOKEINTERFACE:
                // 构造参数污染的集合 argTaint
                final List<Set<T>> argTaint = new ArrayList<Set<T>>(argTypes.length);
                for (int i = 0; i < argTypes.length; i++) {
                    argTaint.add(null);
                }

                for (int i = 0; i < argTypes.length; i++) {
                    Type argType = argTypes[i];
                    if (argType.getSize() > 0) {
                        for (int j = 0; j < argType.getSize() - 1; j++) {
                            pop();
                        }//根据参数类型大小，从栈顶获取入参，参数入栈是从右到左的
                        argTaint.set(argTypes.length - 1 - i, pop());
                    }
                }

                Set<T> resultTaint;
                if (name.equals("<init>")) {
                    // Pass result taint through to original taint set; the initialized object is directly tainted by
                    // parameters
                    // 构造方法的调用，意味着参数0可以污染返回值 就将污点传递到原始污点集合中
                    resultTaint = argTaint.get(0);
                } else {
                    resultTaint = new HashSet<>();
                }

                // If calling defaultReadObject on a tainted ObjectInputStream, that taint passes to "this"
                if (owner.equals("java/io/ObjectInputStream") && name.equals("defaultReadObject") && desc.equals("()V")) {
                    savedVariableState.localVars.get(0).addAll(argTaint.get(0));
                }
                //给了一个白名单  如何在白名单 如果匹配到 就添加污点索引
                for (Object[] passthrough : PASSTHROUGH_DATAFLOW) {
                    if (passthrough[0].equals(owner) && passthrough[1].equals(name) && (passthrough[2].equals(desc) || passthrough[2].equals("*"))) {
                        for (int i = 3; i < passthrough.length; i++) {
                            resultTaint.addAll(argTaint.get((Integer)passthrough[i]));
                        }
                    }
                }

                if (passthroughDataflow != null) {
                    Set<Integer> passthroughArgs = passthroughDataflow.get(methodHandle);
                    if (passthroughArgs != null) {
                        for (int arg : passthroughArgs) {
                            resultTaint.addAll(argTaint.get(arg));
                        }
                    }
                }
                //如果对象实现了java.util.Collection或java.util.Map接口，则假定任何接受对象作为参数的方法都会污染该集合。假定任何返回对象的方法都返回该集合的污点。
                // Heuristic; if the object implements java.util.Collection or java.util.Map, assume any method accepting an object
                // taints the collection. Assume that any method returning an object returns the taint of the collection.
                if (opcode != Opcodes.INVOKESTATIC && argTypes[0].getSort() == Type.OBJECT) {
                    Set<ClassReference.Handle> parents = inheritanceMap.getSuperClasses(new ClassReference.Handle(argTypes[0].getClassName().replace('.', '/')));
                    if (parents != null && (parents.contains(new ClassReference.Handle("java/util/Collection")) ||
                            parents.contains(new ClassReference.Handle("java/util/Map")))) {
                        for (int i = 1; i < argTaint.size(); i++) {
                            argTaint.get(0).addAll(argTaint.get(i));
                        }
                        //getSort() 方法，可以确定它是一个普通类、数组还是基本类型 Type.OBJECT表示返回类型是一个普通类  Type.ARRAY表示返回类型是一个数组
                        if (returnType.getSort() == Type.OBJECT || returnType.getSort() == Type.ARRAY) {
                            resultTaint.addAll(argTaint.get(0));
                        }
                    }
                }
                //todo 测试 当调用get的时候 那么返回值因为是为污点的
                if (flag){
                    resultTaint.add((T) "arg1");
                    flag=false;
                }

                //如果被调用方法有返回值，那么调用方法体需要将方法返回时结果污点标记设置到返回值上,实现对返回值的污点追踪 也就是重新加载到栈上面去
                if (retSize > 0) {
                    push(resultTaint);
                    for (int i = 1; i < retSize; i++) {
                        push();
                    }
                }
                break;
            default:
                throw new IllegalStateException("Unsupported opcode: " + opcode);
        }

        super.visitMethodInsn(opcode, owner, name, desc, itf);

        sanityCheck();
    }

    @Override
    public void visitInvokeDynamicInsn(String name, String desc, Handle bsm, Object... bsmArgs) {
        int argsSize = 0;
        for (Type type : Type.getArgumentTypes(desc)) {
            argsSize += type.getSize();
        }
        int retSize = Type.getReturnType(desc).getSize();

        for (int i = 0; i < argsSize; i++) {
            pop();
        }
        for (int i = 0; i < retSize; i++) {
            push();
        }

        super.visitInvokeDynamicInsn(name, desc, bsm, bsmArgs);

        sanityCheck();
    }

    @Override
    public void visitJumpInsn(int opcode, Label label) {
        switch (opcode) {
            case Opcodes.IFEQ:
            case Opcodes.IFNE:
            case Opcodes.IFLT:
            case Opcodes.IFGE:
            case Opcodes.IFGT:
            case Opcodes.IFLE:
            case Opcodes.IFNULL:
            case Opcodes.IFNONNULL:
                pop();
                break;
            case Opcodes.IF_ICMPEQ:
            case Opcodes.IF_ICMPNE:
            case Opcodes.IF_ICMPLT:
            case Opcodes.IF_ICMPGE:
            case Opcodes.IF_ICMPGT:
            case Opcodes.IF_ICMPLE:
            case Opcodes.IF_ACMPEQ:
            case Opcodes.IF_ACMPNE:
                pop();
                pop();
                break;
            case Opcodes.GOTO:
                break;
            case Opcodes.JSR:
                push();
                super.visitJumpInsn(opcode, label);
                return;
            default:
                throw new IllegalStateException("Unsupported opcode: " + opcode);
        }

        mergeGotoState(label, savedVariableState);

        super.visitJumpInsn(opcode, label);

        sanityCheck();
    }

    @Override
    public void visitLabel(Label label) {
        if (gotoStates.containsKey(label)) {
            savedVariableState = new SavedVariableState(gotoStates.get(label));
        }
        if (exceptionHandlerLabels.contains(label)) {
            // Add the exception to the stack
            push(new HashSet<T>());
        }

        super.visitLabel(label);

        sanityCheck();
    }

    @Override
    public void visitLdcInsn(Object cst) {
        if (cst instanceof Long || cst instanceof Double) {
            push();
            push();
        } else {
            push();
        }

        super.visitLdcInsn(cst);

        sanityCheck();
    }

    @Override
    public void visitIincInsn(int var, int increment) {
        // No effect on stack
        super.visitIincInsn(var, increment);

        sanityCheck();
    }

    @Override
    public void visitTableSwitchInsn(int min, int max, Label dflt, Label... labels) {
        // Operand stack has a switch index which gets popped
        pop();

        // Save the current state with any possible target labels
        mergeGotoState(dflt, savedVariableState);
        for (Label label : labels) {
            mergeGotoState(label, savedVariableState);
        }

        super.visitTableSwitchInsn(min, max, dflt, labels);

        sanityCheck();
    }

    @Override
    public void visitLookupSwitchInsn(Label dflt, int[] keys, Label[] labels) {
        // Operand stack has a lookup index which gets popped
        pop();

        // Save the current state with any possible target labels
        mergeGotoState(dflt, savedVariableState);
        for (Label label : labels) {
            mergeGotoState(label, savedVariableState);
        }
        super.visitLookupSwitchInsn(dflt, keys, labels);

        sanityCheck();
    }

    @Override
    public void visitMultiANewArrayInsn(String desc, int dims) {
        for (int i = 0; i < dims; i++) {
            pop();
        }
        push(); //未测试...

        super.visitMultiANewArrayInsn(desc, dims);

        sanityCheck();
    }

    @Override
    public AnnotationVisitor visitInsnAnnotation(int typeRef, TypePath typePath, String desc, boolean visible) {
        return super.visitInsnAnnotation(typeRef, typePath, desc, visible);
    }

    @Override
    public void visitTryCatchBlock(Label start, Label end, Label handler, String type) {
        exceptionHandlerLabels.add(handler);
        super.visitTryCatchBlock(start, end, handler, type);
    }

    @Override
    public AnnotationVisitor visitTryCatchAnnotation(int typeRef, TypePath typePath, String desc, boolean visible) {
        return super.visitTryCatchAnnotation(typeRef, typePath, desc, visible);
    }

    @Override
    public void visitMaxs(int maxStack, int maxLocals) {
        super.visitMaxs(maxStack, maxLocals);
    }

    @Override
    public void visitEnd() {
        super.visitEnd();
    }

    private void mergeGotoState(Label label, SavedVariableState savedVariableState) {
        if (gotoStates.containsKey(label)) {
            SavedVariableState combinedState = new SavedVariableState(gotoStates.get(label));
            combinedState.combine(savedVariableState);
            gotoStates.put(label, combinedState);
        } else {
            gotoStates.put(label, new SavedVariableState(savedVariableState));
        }
    }

    private void sanityCheck() {
        if (analyzerAdapter.stack != null && savedVariableState.stackVars.size() != analyzerAdapter.stack.size()) {
            throw new IllegalStateException("Bad stack size.");
        }
    }

    protected Set<T> getStackTaint(int index) {
        return savedVariableState.stackVars.get(savedVariableState.stackVars.size()-1-index);
    }
    protected void setStackTaint(int index, T ... possibleValues) {
        Set<T> values = new HashSet<T>();
        for (T value : possibleValues) {
            values.add(value);
        }
        savedVariableState.stackVars.set(savedVariableState.stackVars.size()-1-index, values);
    }
    protected void setStackTaint(int index, Collection<T> possibleValues) {
        Set<T> values = new HashSet<T>();
        values.addAll(possibleValues);
        savedVariableState.stackVars.set(savedVariableState.stackVars.size()-1-index, values);
    }

    protected Set<T> getLocalTaint(int index) {
        return savedVariableState.localVars.get(index);
    }
    protected void setLocalTaint(int index, T ... possibleValues) {
        // 其中"T ... possibleValues"代表接收到的参数作为数组传递给方法
        Set<T> values = new HashSet<T>();
        for (T value : possibleValues) {
            values.add(value);
        }
        savedVariableState.localVars.set(index, values);
    }
    protected void setLocalTaint(int index, Collection<T> possibleValues) {
        Set<T> values = new HashSet<T>();
        values.addAll(possibleValues);
        savedVariableState.localVars.set(index, values);
    }

    protected static final boolean couldBeSerialized(SerializableDecider serializableDecider, InheritanceMap inheritanceMap, ClassReference.Handle clazz) {
        if (Boolean.TRUE.equals(serializableDecider.apply(clazz))) {
            return true;
        }
        //返回一个不可修改的set集合 获取该class所有的子类映射  serializableDecider.apply方法主要判断是否继承了Serializable以及是否是黑名单的类
        Set<ClassReference.Handle> subClasses = inheritanceMap.getSubClasses(clazz);
        if (subClasses != null) {
            for (ClassReference.Handle subClass : subClasses) {
                if (Boolean.TRUE.equals(serializableDecider.apply(subClass))) {
                    return true;
                }
            }
    }
        return false;
    }
}
