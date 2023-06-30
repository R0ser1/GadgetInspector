package gadgetinspector;

import com.google.common.reflect.ClassPath;

import java.io.IOException;
import java.io.InputStream;
import java.net.*;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.Collection;

public class ClassResourceEnumerator {
    private final ClassLoader classLoader;
    public ClassResourceEnumerator(ClassLoader classLoader) throws IOException {
        this.classLoader = classLoader;
    }

    public Collection<ClassResource> getAllClasses() throws IOException {
        /*
            这里是先调用getRuntimeClasses然后获取到的rt.jar下的所有类信息 然后再加载我们传入需要分析的jar等的classload去加载
            然后获取待分析的所有Class文件然后和rt.jar下的class文件合并。
         */
        Collection<ClassResource> result = new ArrayList<>(getRuntimeClasses());
        //加入rt类的大小
        ConfigHelper.rt_jar_size= result.size();

        if (ConfigHelper.onlyJDK)
            return result;
        for (ClassPath.ClassInfo classInfo : ClassPath.from(classLoader).getAllClasses()) {
            //下面只是为了测试使用 为了更好的理解整个关系
//            if (classInfo.getName().startsWith("com.test")){
//                result.add(new ClassLoaderClassResource(classLoader, classInfo.getResourceName()));
//            }
            result.add(new ClassLoaderClassResource(classLoader, classInfo.getResourceName()));
        }
        return result;
    }

    private Collection<ClassResource> getRuntimeClasses() throws IOException {
        /*
        JDK8 这里通过String.class 获取rt.jar的位置。然后通过URLClassLoader 去加载它.然后这里通过getAllClasses方法获取所有的Class文件
        遍历出来 通过实现的ClassLoaderClassResource方法 记录的classLoader和resourceName
        其中resourceName的形式为：com/sun/java/accessibility/AccessBridge$1.class
        然后通过ArrayList记录下来返回这个数组列表
        */
        URL stringClassUrl = Object.class.getResource("String.class");
        URLConnection connection = stringClassUrl.openConnection();
        Collection<ClassResource> result = new ArrayList<>();
        if (connection instanceof JarURLConnection && ConfigHelper.useJDK) {
            URL runtimeUrl = ((JarURLConnection) connection).getJarFileURL();
            //todo 设置为null避免加载工具依赖的类
            URLClassLoader classLoader = new URLClassLoader(new URL[]{runtimeUrl},null);

            for (ClassPath.ClassInfo classInfo : ClassPath.from(classLoader).getAllClasses()) {
                //测试使用 方便快速跟进
//                if (classInfo.getName().startsWith("com.sun.scenario.effect.impl.EffectPeer")){
//                    result.add(new ClassLoaderClassResource(classLoader, classInfo.getResourceName()));
//                }
//                if (classInfo.getName().startsWith("java.lang")||classInfo.getName().startsWith("java.util")||classInfo.getName().startsWith("java.io")){
//                    result.add(new ClassLoaderClassResource(classLoader, classInfo.getResourceName()));
//                }

                result.add(new ClassLoaderClassResource(classLoader, classInfo.getResourceName()));
            }
            return result;
        }

            // Try finding all the JDK classes using the Java9+ modules method:
//        Java 9 中，Java 采用了一种新的模块化系统，rt.jar 文件被拆分成多个模块，不再单独存在 采用以下的方式
            try {
                FileSystem fs = FileSystems.getFileSystem(URI.create("jrt:/"));
                Files.walk(fs.getPath("/")).forEach(p -> {
                    if (p.toString().toLowerCase().endsWith(".class")) {
                        result.add(new PathClassResource(p));
                    }
                });
            } catch (ProviderNotFoundException e) {
                // Do nothing; this is expected on versions below Java9
            }

            return result;
        }

        public static interface ClassResource {
            public InputStream getInputStream() throws IOException;

            public String getName();
        }

        private static class PathClassResource implements ClassResource {
            private final Path path;

            private PathClassResource(Path path) {
                this.path = path;
            }

            @Override
            public InputStream getInputStream() throws IOException {
                return Files.newInputStream(path);
            }

            @Override
            public String getName() {
                return path.toString();
            }
        }

        private static class ClassLoaderClassResource implements ClassResource {
            private final ClassLoader classLoader;
            private final String resourceName;

            private ClassLoaderClassResource(ClassLoader classLoader, String resourceName) {
                this.classLoader = classLoader;
                this.resourceName = resourceName;
            }

            @Override
            public InputStream getInputStream() throws IOException {
                return classLoader.getResourceAsStream(resourceName);
            }

            @Override
            public String getName() {
                return resourceName;
            }
        }
    }
