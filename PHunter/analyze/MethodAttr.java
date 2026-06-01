package analyze;

import soot.*;
import symbolicExec.MethodDigest;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

public class MethodAttr implements Comparable<MethodAttr>, Serializable {
    private static final long serialVersionUID = 1L;

    public static final String ClassRepresentation = "X";
    public static final String ArrayClassRepresentation = "X[]";

    public ClassAttr declaredClass;
    public String signature;
    public int modifiers;
    public String fuzzy;
    public String subSignature;
    public transient Body body;
    public boolean hasBody;
    public String returnType;
    public List<String> parameterTypes = new ArrayList<>();
    public MethodDigest digest;

    public int startLinenumber;
    public int endLinenumber;

    public transient List<MethodAttr> callee = new LinkedList<>();
    public transient List<MethodAttr> caller = new LinkedList<>();
    public List<String> calleeFuzzy = new LinkedList<>();
    public List<String> callerFuzzy = new LinkedList<>();
    public transient Set<SootField> fieldRef = new HashSet<>();
    public List<String> fuzzyFieldRef = null;

    //    private final Set<String> readField = new HashSet<>();
//    private final Set<String> writeField = new HashSet<>();
    public int getStartLinenumber() {
        return startLinenumber;
    }

    public void setStartLinenumber(int startLinenumber) {
        this.startLinenumber = startLinenumber;
    }

    public int getEndLinenumber() {
        return endLinenumber;
    }

    public void setEndLinenumber(int endLinenumber) {
        this.endLinenumber = endLinenumber;
    }

    public MethodAttr(Body body) { // for method
        this.body = body;
        SootMethod method = body.getMethod();
        signature = method.getSignature();
        fuzzy = getFuzzyForm(method);
        modifiers = method.getModifiers();
        subSignature = method.getSubSignature();
        hasBody = true;
        returnType = method.getReturnType().toString();
        for (Type t : method.getParameterTypes()) {
            parameterTypes.add(t.toString());
        }
    }

    public MethodAttr(SootMethod method) { // for no body method
        signature = method.getSignature();
        fuzzy = getFuzzyForm(method);
        modifiers = method.getModifiers();
        subSignature = method.getSubSignature();
        hasBody = method.hasActiveBody();
        returnType = method.getReturnType().toString();
        for (Type t : method.getParameterTypes()) {
            parameterTypes.add(t.toString());
        }
    }

    public boolean hasActiveBody() {
        return hasBody || digest != null;
    }

    public MethodDigest ensureDigest(List<Integer> patchRelatedLines) {
        if (digest != null) {
            return digest;
        }
        if (body == null) {
            return null;
        }
        digest = new MethodDigest(body, patchRelatedLines);
        return digest;
    }


    public void getFieldFuzzyForm() {
        if (fieldRef.isEmpty())
            return;
        this.fuzzyFieldRef = new LinkedList<>();
        for (SootField f : fieldRef) {
            if (f == null) {
                fuzzyFieldRef.add("java.lang.Object,");
                continue;
            }
            StringBuilder sb = new StringBuilder();
            addType(f.getType(), sb);
            fuzzyFieldRef.add(sb.toString());
        }
    }


    private String getFuzzyForm(SootMethod m) {
        if (m == null)
            return null;
        StringBuilder sb = new StringBuilder();
        if (m.isStatic())
            sb.append("static,");
        addType(m.getReturnType(), sb);
        for (Type t : m.getParameterTypes())
            addType(t, sb);
        return sb.toString();
    }

    private void addType(Type t, StringBuilder sb) {
        if (t == null) {
            sb.append("java.lang.Object,");
            return;
        }
        try {
            if (t instanceof RefType) {
                RefType refType = (RefType) t;
                SootClass sootClass = resolveSootClass(refType);
                if (sootClass == null) {
                    sb.append(t).append(",");
                } else if (sootClass.isJavaLibraryClass()
                        || isAndroidClass(sootClass.getName())) {
                    sb.append(t).append(",");
                } else if (sootClass.isApplicationClass()
                        || sootClass.isPhantomClass()) {
                    sb.append("X,");
                } else {
                    sb.append(t).append(",");
                }
                return;
            }
            if (t instanceof ArrayType &&
                    ((ArrayType) t).baseType instanceof RefType) {
                RefType refType = (RefType) ((ArrayType) t).baseType;
                SootClass sootClass = resolveSootClass(refType);
                if (sootClass == null) {
                    sb.append(t).append(",");
                } else if (sootClass.isJavaLibraryClass()
                        || isAndroidClass(sootClass.getName())) {
                    sb.append(t).append(",");
                } else if (sootClass.isApplicationClass()
                        || sootClass.isPhantomClass()) {
                    sb.append("X[],");
                } else {
                    sb.append(t).append(",");
                }
                return;
            }
            sb.append(t).append(",");
        } catch (RuntimeException ex) {
            // Some libraries contain broken/phantom type metadata. Fall back to raw type text.
            sb.append(t).append(",");
        }
    }

    private SootClass resolveSootClass(RefType refType) {
        try {
            return refType.getSootClass();
        } catch (RuntimeException ex) {
            return null;
        }
    }


    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }


    public void addCallee(MethodAttr callee) {
        if (this.callee == null) {
            this.callee = new LinkedList<>();
        }
        this.callee.add(callee);
        if (callee != null && callee.fuzzy != null) {
            this.calleeFuzzy.add(callee.fuzzy);
        }
    }

    public void addCaller(MethodAttr caller) {
        if (this.caller == null) {
            this.caller = new LinkedList<>();
        }
        this.caller.add(caller);
        if (caller != null && caller.fuzzy != null) {
            this.callerFuzzy.add(caller.fuzzy);
        }
    }

    public static boolean isAndroidClass(String name) {
        return name.startsWith("android.") ||
                name.startsWith("androidx.") ||
                name.startsWith("dalvik.") ||
                name.startsWith("org.w3c.dom");
    }

//    public void addReadField(String fieldSignature) {
//        readField.add(fieldSignature);
//    }
//
//    public void addWriteField(String fieldSignature) {
//        writeField.add(fieldSignature);
//    }
//
//    public void addJavaLibraryCall(String methodSignature) {
//        javaLibraryCall.add(methodSignature);
//    }
//
//    public void addAndroidFrameworkCall(String methodSignature) {
//        androidFrameworkLibraryCall.add(methodSignature);
//    }

    @Override
    public int hashCode() {
        int hash = 0;
        String str = signature;
        int itr = str.length() / 32;
        if (str.length() % 32 != 0)
            itr += 1;
        for (int i = 0; i < itr; i++) {
            if (i != itr - 1)
                hash += str.substring(32 * i, 32 * i + 32).hashCode();
            else hash += str.substring(32 * i).hashCode();
        }
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        MethodAttr other = (MethodAttr) obj;
        if (this.signature == null) {
            return other.signature == null;
        } else return this.signature.equals(other.signature);
    }

    public String toString() {
        return this.signature;
    }

    @Override
    public int compareTo(MethodAttr o) {
        return this.signature.compareTo(o.signature);
    }
}

