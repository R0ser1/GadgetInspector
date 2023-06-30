package gadgetinspector;

import gadgetinspector.config.ConfigRepository;
import gadgetinspector.config.GIConfig;
import gadgetinspector.data.ClassReference;
import gadgetinspector.data.DataLoader;
import jdk.nashorn.internal.runtime.regexp.joni.constants.OPCode;
import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Level;
import org.apache.log4j.PatternLayout;
import org.objectweb.asm.Opcodes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

/**
 * Main entry point for running an end-to-end analysis. Deletes all data files before starting and writes discovered
 * gadget chains to gadget-chains.txt.
 */
public class GadgetInspector {
    private static final Logger LOGGER = LoggerFactory.getLogger(GadgetInspector.class);

    private static void printUsage() {
        System.out.println("================================================\n" +
                "Usage：请使用以下参数 并且最后加入需要分析的路径\n" +
                "================================================\n" +
                "--onlyJDK：仅扫描jdk\n" +
                "--noJDK：不使用JDK\n" +
                "--resume：启动时不删除所有dat数据文件\n" +
                "--boot：指定该jar为SpringBoot项目jar包\n" +
                "--onlyClass：只扫描Class文件进行测试\n" +
                "--readObjectissink：使用readObject为Sink\n" +
                "--useJDKchain：默认不输出全部为JDK类的链\n" +
                "--config：挖掘什么样的gadget chains(Webservice、jserial...) 默认为反序列化\n" +
                "--similarLevel x：x代表数字 中间路径沿重过高的问题 默认4\n" +
                "--maxChainLength x：x代表数字 挖掘仅输出小于该链长度的链\n" +
                "--maxRepeatBranchesTimes x：x代表数字 解决最大节点最大的访问次数 默认10\n" +
                "--noTaintTrack：不使用污点分析，将会把所有链都搜索出来,坏处是需要大量的人工审计\n" +
                "--sinks：指定Sinik(JNDI、XXE、EXEC、REFLECT、FILEIO、JDBC、EL、SQL、SSRF、SSTI、DESERIALIZE、XPATH、EXPRESSION、REDIRECT) 默认全部");

    }
    static {
        try {
            Path currentDir = Paths.get("").toAbsolutePath();
            Path gadgetResultDir = currentDir.resolve("gadget-result");
            Path resultCacheDir = gadgetResultDir.resolve("result_cache");
            if (!Files.exists(gadgetResultDir)) {
                Files.createDirectory(gadgetResultDir);
                if (!Files.exists(resultCacheDir)){
                    Files.createDirectory(resultCacheDir);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {

            printUsage();
            System.exit(1);
        }

        configureLogging();
        //是否不删除所有的dat文件
        boolean resume = false;
        //扫描springboot
        boolean boot = false;
        //fuzz类型，默认java原生序列化
        GIConfig config = ConfigRepository.getConfig("jserial");
        int argIndex = 0;
        while (argIndex < args.length) {
            String arg = args[argIndex];
            if (!arg.startsWith("--")) {
                break;
            }
            if (arg.equals("--resume")) {
                //不删除dat文件
                resume = true;
            } else if (arg.equals("--config")) {
                //--config参数指定fuzz类型
                config = ConfigRepository.getConfig(args[++argIndex]);
                if (config == null) {
                    throw new IllegalArgumentException("Invalid config name: " + args[argIndex]);
                }
                ConfigHelper.giConfig = config;
            }else if (arg.equals("--noTaintTrack")) {
                //是否污点分析，若不使用污点分析，将会把所有链都搜索出来，好处是不会遗漏，坏处是需要大量的人工审计
                ConfigHelper.taintTrack = false;
            }else if (arg.equals("--maxChainLength")) {
                //仅输出小于该链长度的链
                ConfigHelper.maxChainLength = Integer.parseInt(args[++argIndex]);
            }else if(arg.equals("--maxRepeatBranchesTimes")){
                // 解决最大节点最大的访问次数
                ConfigHelper.maxRepeatBranchesTimes = Integer.parseInt(args[++argIndex]);
            }else if (arg.equals("--similarLevel")) {
                //解决中间路径沿重过高的问题 默认4
                ConfigHelper.similarLevel = Integer.parseInt(args[++argIndex]);
            }else if (arg.equals("--onlyJDK")) {
                //仅扫描jdk
                ConfigHelper.onlyJDK = true;
            }else if (arg.equals("--noJDK")) {
                //不使用JDK
                ConfigHelper.useJDK = false;
            }else if (arg.equals("--readObjectissink")){
                ConfigHelper.readObjectissink = true;
            }else if (arg.equals("--useJDKchain")){
                ConfigHelper.useJDKchain = true;
            }else if (arg.equals("--boot")){
                //扫描springboot
                boot = true;
            }else if (arg.equals("--onlyClass")){
                //扫描springboot
                ConfigHelper.onlyClass = true;
            }else if (arg.equals("--sinks")) {
                for (int i = argIndex + 1; i < args.length - 1; i++) {
                    if (!args[i].startsWith("--")) {
                        ConfigHelper.sinks.add(args[++argIndex]);
                    }
                }
            }

            argIndex += 1;
        }

        List<Path> pathList = new ArrayList<>();
        ClassLoader classLoader = initJarData(args, boot, argIndex, pathList);
        final ClassResourceEnumerator classResourceEnumerator = new ClassResourceEnumerator(classLoader);

        if (!resume) {
            // Delete all existing dat files
            LOGGER.info("Deleting stale data...");
            for (String datFile : Arrays.asList("classes.dat", "methods.dat", "inheritanceMap.dat",
                    "passthrough.dat", "callgraph.dat", "sources.dat", "methodimpl.dat")) {
                final Path path = Paths.get(datFile);
                if (Files.exists(path)) {
                    Files.delete(path);
                }
            }
        }
        beginDiscovery(config, classResourceEnumerator, pathList);

    }
    private static ClassLoader initJarData(String[] args, boolean boot, int argIndex, List<Path> pathList) throws IOException {
        ClassLoader classLoader = null;
        if (!ConfigHelper.onlyJDK) {
            //程序参数的最后一部分，即最后一个具有前缀--的参数（例：--resume）后
            if (args.length == argIndex + 1 && args[argIndex].toLowerCase().endsWith(".war")) {
                //加载war文件
                Path path = Paths.get(args[argIndex]);
                LOGGER.info("Using WAR classpath: " + path);
                //实现为URLClassLoader，加载war包下的WEB-INF/lib和WEB-INF/classes
                classLoader = Util.getWarClassLoader(path);
            } else if (args.length == argIndex + 1 && args[argIndex].toLowerCase().endsWith(".jar")
                    && boot) {
                Path path = Paths.get(args[argIndex]);
                LOGGER.info("Using JAR classpath: " + path);
                //实现为URLClassLoader，加载jar包下的BOOT-INF/lib和BOOT-INF/classes
                classLoader = Util.getJarAndLibClassLoader(path);
            }else if (!args[argIndex].toLowerCase().endsWith(".jar")&&ConfigHelper.onlyClass){
                Path path = Paths.get(args[argIndex]);
                LOGGER.info("Using JAR classpath: " + path);
                classLoader = Util.getClassClasLoader(path);
            }
            else {

                AtomicInteger jarCount = new AtomicInteger(0);
                for (int i = 0; i < args.length - argIndex; i++) {
                    String pathStr = args[argIndex + i];
                    if (!pathStr.endsWith(".jar")) {
                        //todo 主要用于大批量的挖掘链
                        //非.jar结尾，即目录，需要遍历目录找出所有jar文件
                        File file = Paths.get(pathStr).toFile();
                        if (file == null || !file.exists())
                            continue;
                        Files.walkFileTree(file.toPath(), new SimpleFileVisitor<Path>() {
                            @Override
                            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                                if (file.getFileName().toString().endsWith(".jar")) {
                                    File readFile = file.toFile();
                                    Path path = Paths.get(readFile.getAbsolutePath());
                                    if (Files.exists(path)) {
                                        if (jarCount.incrementAndGet()
                                                <= ConfigHelper.maxJarCount) {
                                            pathList.add(path);
                                        }
                                    }
                                }
                                return FileVisitResult.CONTINUE;
                            }
                        });

                        continue;
                    }
                    Path path = Paths.get(pathStr).toAbsolutePath();
                    if (!Files.exists(path)) {
                        throw new IllegalArgumentException("Invalid jar path: " + path);
                    }
                    pathList.add(path);
                }
                LOGGER.info("Using classpath: " + Arrays.toString(pathList.toArray()));
                //实现为URLClassLoader，加载所有指定的jar
                classLoader = Util.getJarClassLoader(pathList.toArray(new Path[0]));
            }
        }
        return classLoader;
    }

    private static void beginDiscovery(GIConfig config,
                                       ClassResourceEnumerator classResourceEnumerator,
                                       List<Path> pathList) throws Exception{
        /*
        * todo 测试 查找特定的一些东西
         */
//        if (!Files.exists(Paths.get("Findinfo.dat"))) {
//            LOGGER.info("Running Findinfo discovery...");
//
//            FindinfoVisitor findinfoVisitor = new FindinfoVisitor(Opcodes.ASM9);
//            findinfoVisitor.discover(classResourceEnumerator);
//            return;
//        }
        /*
            通过asm分析类文件包含的的类、方法信息 然后存储起来  其中包括classes.dat methods.dat inheritanceMap.dat
        */
        if (!Files.exists(Paths.get("classes.dat")) || !Files.exists(Paths.get("methods.dat"))
                || !Files.exists(Paths.get("inheritanceMap.dat"))) {
            LOGGER.info("Running method discovery...");

            MethodDiscovery methodDiscovery = new MethodDiscovery();
            methodDiscovery.discover(classResourceEnumerator);
            methodDiscovery.save();
        }
        /*
        分析各个方法 污点传递 模拟JVM 堆栈传递然后污点传递 并收集存储能影响到返回值的方法
        类名 方法名 方法描述 能污染返回值的参数索引1,能污染返回值的参数索引2
         */
        if (!Files.exists(Paths.get("passthrough.dat"))) {
            LOGGER.info("Analyzing methods for passthrough dataflow...");
            PassthroughDiscovery passthroughDiscovery = new PassthroughDiscovery();
            passthroughDiscovery.discover(classResourceEnumerator, config);
            passthroughDiscovery.save();
        }
        /*
        记录调用者方法和被调用者方法的参数关联
        调用者类名 | 调用者方法 | 调用者方法描述 | 被调用者类名 | 被调用者方法 | 被调用者方法描述 | 调用者方法参索引 | 调用者类的字段名 | 被调用者方法参数索引
         */
        if (!Files.exists(Paths.get("callgraph.dat"))) {
            LOGGER.info("Analyzing methods in order to build a call graph...");
            CallGraphDiscovery callGraphDiscovery = new CallGraphDiscovery();
            callGraphDiscovery.discover(classResourceEnumerator, config);
            callGraphDiscovery.save();
        }

        /*
            根据决策器来 搜索可用的source也就是入口点 后续保存为
            类名 | 方法名 | 方法描述 | 污染参数索引
         */
        if (!Files.exists(Paths.get("sources.dat"))) {
            LOGGER.info("Discovering gadget chain source methods...");
            SourceDiscovery sourceDiscovery = config.getSourceDiscovery();
            sourceDiscovery.discover();
            sourceDiscovery.save();
        }

        /*
            从source到slink进行整合分析
         */
        {
            LOGGER.info("Searching call graph for gadget chains...");
            GadgetChainDiscovery gadgetChainDiscovery = new GadgetChainDiscovery(config);
            gadgetChainDiscovery.discover(pathList);
        }

        LOGGER.info("Analysis complete!");
    }

    private static void configureLogging() {
        ConsoleAppender console = new ConsoleAppender();
        String PATTERN = "%d %c [%p] %m%n";
        console.setLayout(new PatternLayout(PATTERN));
        console.setThreshold(Level.INFO);
        console.activateOptions();
        org.apache.log4j.Logger.getRootLogger().addAppender(console);
    }
}
