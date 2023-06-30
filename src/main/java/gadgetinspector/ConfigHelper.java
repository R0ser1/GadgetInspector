package gadgetinspector;

import gadgetinspector.config.GIConfig;

import java.util.HashSet;
import java.util.Set;

public class ConfigHelper {
    public static int maxRepeatBranchesTimes = 0;
    public static int similarLevel = 3;
    public static int maxChainLength = Integer.MAX_VALUE;
    public static boolean taintTrack = true;
    public static GIConfig giConfig;
    public static boolean onlyJDK = false;
    public static boolean useJDK = true;
    public static int maxJarCount = Integer.MAX_VALUE;
    public static Set<String> sinks = new HashSet<>();
    public static boolean readObjectissink=false;
    public static int rt_jar_size=19827; //JDK8我这里默认是这么多
    public static boolean useJDKchain=false;
    public static boolean onlyClass=false;

}
