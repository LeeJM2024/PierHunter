package analyze;

import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.Type;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class SootCallGraph {

    boolean isAPK;
    private final Set<String> targetClasses;
    private final Set<String> targetPackagePrefixes;
    private final boolean limitToTargetClasses;

    ConcurrentHashMap<SootMethod, List<SootMethod>> callSites = new ConcurrentHashMap<>();

    Map<SootMethod, List<SootMethod>> callGraph = new HashMap<>();

    Map<SootClass, Set<SootClass>> classHierarchy = new HashMap<>();

    Set<SootClass> allSootClasses = new HashSet<>();

    ConcurrentHashMap<SootMethod, MethodAttr> sootMethodMethodAttrMap = new ConcurrentHashMap<>();

    public SootCallGraph(boolean isAPK) {
        this(isAPK, Collections.emptySet());
    }

    public SootCallGraph(boolean isAPK, Set<String> targetClasses) {
        this.isAPK = isAPK;
        this.targetClasses = normalizeTargets(targetClasses);
        this.targetPackagePrefixes = buildTargetPackagePrefixes(this.targetClasses);
        this.limitToTargetClasses = !this.targetClasses.isEmpty();
    }

    public void buildSootCallGraph() {
        if (isAPK) {
            for (SootClass clazz : Scene.v().getApplicationClasses()) {
                if (shouldAnalyzeApplicationClass(clazz)) {
                    allSootClasses.add(clazz);
                }
            }
        } else {
            for (SootClass clazz : Scene.v().getClasses()) {
                if (!isAndroidFrameworkCall(clazz.getName()))
                    allSootClasses.add(clazz);
            }
        }
        genSubClassGraph();
        for (SootClass c : this.allSootClasses) {
            for (SootMethod m : c.getMethods())
                handleEachMethod(m);
        }
    }

    private Set<String> normalizeTargets(Set<String> rawTargets) {
        Set<String> normalized = new LinkedHashSet<>();
        if (rawTargets == null || rawTargets.isEmpty()) {
            return normalized;
        }
        for (String target : rawTargets) {
            if (target == null) {
                continue;
            }
            String value = target.trim();
            if (value.endsWith(".*")) {
                value = value.substring(0, value.length() - 2);
            }
            if (value.endsWith(".")) {
                value = value.substring(0, value.length() - 1);
            }
            if (!value.isEmpty()) {
                normalized.add(value);
            }
        }
        return normalized;
    }

    private Set<String> buildTargetPackagePrefixes(Set<String> targets) {
        Set<String> prefixes = new LinkedHashSet<>();
        for (String target : targets) {
            if (target == null || target.isEmpty()) {
                continue;
            }
            prefixes.add(target + ".");
            int lastDot = target.lastIndexOf('.');
            if (lastDot > 0) {
                prefixes.add(target.substring(0, lastDot + 1));
            }
        }
        return prefixes;
    }

    private boolean shouldAnalyzeApplicationClass(SootClass clazz) {
        if (!clazz.isApplicationClass()) {
            return false;
        }
        String className = clazz.getName();
        if (isAndroidFrameworkCall(className)) {
            return false;
        }
        if (!limitToTargetClasses) {
            return true;
        }
        if (targetClasses.contains(className)) {
            return true;
        }
        for (String packagePrefix : targetPackagePrefixes) {
            if (className.startsWith(packagePrefix)) {
                return true;
            }
        }
        return false;
    }

    public void genSubClassGraph() {
        for (SootClass c : this.allSootClasses) {
            this.classHierarchy.put(c, new HashSet<>());
            this.classHierarchy.get(c).add(c);
        }
        for (SootClass c : this.allSootClasses) {
            while (c.hasSuperclass()) {
                SootClass super_cls = c.getSuperclass();
                if (this.classHierarchy.get(super_cls) != null) {
                    this.classHierarchy.get(super_cls).add(c);
                }
//                c = super_cls;
//                this.classHierarchy.get(super_cls).add(c);
                c = super_cls;
            }
        }
    }


    public String buildMethodSig(SootMethod m) {
        StringBuilder sig = new StringBuilder();
        sig.append(m.getReturnType()).append(",").append(m.getName()).append(",");
        for (Type t : m.getParameterTypes())
            sig.append(t).append(",");
        return sig.toString();
    }

    public SootMethod dispatch(SootMethod m, SootClass c) {
        String sig = buildMethodSig(m);
        SootClass cur = c;
        while (true) {
            for (SootMethod m1 : cur.getMethods()) {
                if (buildMethodSig(m1).equals(sig))
                    return m1;
            }
            if (!cur.hasSuperclass()) {
                System.out.println("ERROR: cannot reach here");
                return null;
            }
            cur = cur.getSuperclass();
        }
    }

    public void handleEachMethod(SootMethod m) {
        if (isAndroidFrameworkCall(m.getDeclaringClass().getName()))
            return;
        if (this.callGraph.containsKey(m))
            return;
        List<SootMethod> ret = new ArrayList<>();
        if (!this.callSites.containsKey(m)) {
            this.callGraph.put(m, ret);
            return;
        }
        for (SootMethod callee : this.callSites.get(m)) {
            if (callee.isStatic() || callee.isConstructor()) {
                ret.add(callee);
                continue;
            }
            SootClass rcv_class = callee.getDeclaringClass();
            if (rcv_class.isPhantom() || rcv_class.isJavaLibraryClass()) {
                ret.add(callee);
                continue;
            }
            if (this.classHierarchy.get(rcv_class) == null)
                ret.add(callee);
            else
                for (SootClass sub : this.classHierarchy.get(rcv_class)) {
//                    if (sub.isAbstract())
//                        continue;
                    ret.add(dispatch(callee, sub));
                }
        }
        this.callGraph.put(m, ret);
    }

    public static boolean isAndroidFrameworkCall(String classSignature) {
        String[] api_list = {"android.", "androidx.", "dalvik.", "res.",
                "kotlin", "kotlinx", "org.w3c.dom", "org.json"};
        for (String api : api_list) {
            if (classSignature.startsWith(api))
                return true;
        }
        return false;

    }
}
