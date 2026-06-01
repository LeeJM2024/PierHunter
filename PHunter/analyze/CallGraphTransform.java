package analyze;

import soot.*;
import soot.jimple.IfStmt;
import soot.jimple.Jimple;
import soot.jimple.Stmt;

import java.util.*;

public class CallGraphTransform extends BodyTransformer {
    private static final long APK_PROGRESS_INTERVAL_NANOS = 2_000_000_000L;
    private static final int APK_PROGRESS_BAR_WIDTH = 24;
    private static final String APK_PROGRESS_ENABLED_ENV = "PHUNTER_SOOT_PROGRESS";
    private static
    SootCallGraph cg;
    private static long apkProgressStartNanos = 0L;
    private static long apkProgressLastPrintNanos = 0L;
    private static int apkProgressBodies = 0;
    private static String apkProgressName = "";


    public CallGraphTransform(SootCallGraph cg) {
        this.cg = cg;
    }

    public static void beginApkProgress(String apkName) {
        if (!isApkProgressEnabled()) {
            return;
        }
        apkProgressName = apkName == null ? "apk" : apkName;
        apkProgressBodies = 0;
        apkProgressStartNanos = System.nanoTime();
        apkProgressLastPrintNanos = 0L;
        printApkProgress("start", "");
    }

    public static void finishApkProgress() {
        if (!isApkProgressEnabled() || apkProgressStartNanos == 0L) {
            return;
        }
        printApkProgress("done", "");
        apkProgressStartNanos = 0L;
        apkProgressLastPrintNanos = 0L;
        apkProgressBodies = 0;
        apkProgressName = "";
    }

    private static boolean isApkProgressEnabled() {
        String value = System.getenv(APK_PROGRESS_ENABLED_ENV);
        return value == null || !value.trim().equals("0");
    }

    private static void markApkBodyProcessed(SootMethod method) {
        if (!isApkProgressEnabled() || apkProgressStartNanos == 0L) {
            return;
        }
        apkProgressBodies++;
        long now = System.nanoTime();
        if (apkProgressLastPrintNanos == 0L
                || now - apkProgressLastPrintNanos >= APK_PROGRESS_INTERVAL_NANOS) {
            String current = method == null ? "" : method.getSignature();
            printApkProgress("run", current);
            apkProgressLastPrintNanos = now;
        }
    }

    private static void printApkProgress(String phase, String currentMethod) {
        long now = System.nanoTime();
        double elapsedSeconds = apkProgressStartNanos == 0L
                ? 0.0
                : (now - apkProgressStartNanos) / 1_000_000_000.0;
        double rate = elapsedSeconds <= 0.001 ? 0.0 : apkProgressBodies / elapsedSeconds;
        String bar = buildActivityBar(apkProgressBodies);
        StringBuilder sb = new StringBuilder(256);
        sb.append("[phunter-soot] ")
                .append(phase)
                .append(" ")
                .append(bar)
                .append(" apk=")
                .append(apkProgressName)
                .append(" bodies=")
                .append(apkProgressBodies)
                .append(" elapsed=")
                .append(String.format(Locale.ROOT, "%.1fs", elapsedSeconds))
                .append(" rate=")
                .append(String.format(Locale.ROOT, "%.1f/s", rate));
        if (currentMethod != null && !currentMethod.isEmpty()) {
            sb.append(" current=").append(shorten(currentMethod, 120));
        }
        System.out.println(sb.toString());
        System.out.flush();
    }

    private static String buildActivityBar(int count) {
        int cursor = Math.floorMod(count / 50, APK_PROGRESS_BAR_WIDTH);
        StringBuilder sb = new StringBuilder(APK_PROGRESS_BAR_WIDTH + 2);
        sb.append('[');
        for (int i = 0; i < APK_PROGRESS_BAR_WIDTH; i++) {
            sb.append(i == cursor ? '>' : '=');
        }
        sb.append(']');
        return sb.toString();
    }

    private static String shorten(String value, int maxLength) {
        if (value == null || value.length() <= maxLength) {
            return value == null ? "" : value;
        }
        return value.substring(0, maxLength - 3) + "...";
    }

    @Override
    protected void internalTransform(Body b, String phaseName, Map<String, String> options) {

        SootMethod method = b.getMethod();
        if (cg.isAPK) {
            markApkBodyProcessed(method);
        }
//        if (SootCallGraph.isAndroidFrameworkCall(method.getDeclaringClass().getName()))
//            return;
//        if (method.getDeclaringClass().isApplicationClass())
//            return;
        MethodAttr methodAttr = new MethodAttr(b);
//        if (cg.isAPK && method.isStaticInitializer()) {
//            handleStaticInitial(b);
//        }

        boolean flag = false;
        UnitPatchingChain units = b.getUnits();
        for (Unit u : units) {
            if (!cg.isAPK) {
                int l = u.getJavaSourceStartLineNumber();
                if (l > -1 && !flag) {
                    flag = true;
                    methodAttr.startLinenumber = l;
                }
            }
            if (!(u instanceof Stmt))
                continue;
            Stmt t = (Stmt) u;
            if (t.containsFieldRef()) {
                SootField field = t.getFieldRef().getField();
                methodAttr.fieldRef.add(field);
            } else if (t.containsInvokeExpr()) {
                SootMethod callee = t.getInvokeExpr().getMethod();
                cg.callSites.putIfAbsent(method, new ArrayList<>());
                cg.callSites.get(method).add(callee);
            }
        }
        if (!cg.isAPK)
            methodAttr.endLinenumber = b.getUnits().getLast().getJavaSourceStartLineNumber();
        methodAttr.getFieldFuzzyForm();
        cg.sootMethodMethodAttrMap.put(method, methodAttr);
    }

    private Stmt handleDashOBug(Iterator<Unit> itrUnit, SootMethod m) {
        itrUnit.next();
        Unit unit = itrUnit.next();
//        System.out.println(m.getName() + " " + m.getDeclaringClass().getName() + " " + unit.toString());
//        System.out.println(unit.toString());
        IfStmt t = (IfStmt) unit;
        Unit target = t.getTarget();
//        Value value = t.getCondition();
//        ValueBox conbox = t.getConditionBox();
//        Value value = conbox.getValue();
//        List<ValueBox> list = value.getUseBoxes();
//        ValueBox left = list.get(0);
//        Value leftV = left.getValue();
////        System.out.println(leftV.toString());
//        ValueBox right = list.get(1);
//        Value rightV = right.getValue();
////        System.out.println(rightV.toString());
//        GtExpr gtExpr = Jimple.v().newGtExpr(leftV, rightV);
        return Jimple.v().newGotoStmt(target);
//        t.setTarget(expr);

//        GtExpr gt = new GeExpr()
//        Value newcon =  ConditionExpr;
//        con.getType()
    }

    private void handleStaticInitial(Body b) {
        Unit begin = null, end = null;
        SootClass runtimeClass = null;
        Trap first = null;
        boolean flag = false;
        List<Trap> tmpTrap = new LinkedList<>();
        for (Trap trap : b.getTraps()) {
            SootClass clazz = trap.getException();
            SootClass superClazz = clazz.getSuperclass();
            if (superClazz.getName().equals("java.lang.RuntimeException")) {
                runtimeClass = superClazz;
                flag = true;
                if (begin == null) {
                    begin = trap.getBeginUnit();
                }
                end = trap.getEndUnit();
                tmpTrap.add(trap);
            }
        }
        if (flag) {
            for (Trap trap : tmpTrap) {
                trap.setException(runtimeClass);
                trap.setBeginUnit(begin);
                trap.setEndUnit(end);
            }
        }

//        if (flag) {
//            for (Unit unit : b.getUnits()) {
//                if (!(unit instanceof Stmt))
//                    continue;
//                Stmt t = (Stmt) unit;
//                if(t instanceof IdentityStmt){
//                    System.out.println(1);
//                }else if(t instanceof AssignStmt)
//                    System.out.println(2);
////                if (t.containsInvokeExpr()) {
////                    SootClass runtimeEx = t.getInvokeExpr().getMethod().getDeclaringClass();
////                    if (runtimeEx.getName().equals("java.lang.RuntimeException")) {
////                        b.getUnits().remove(unit);
////                        break;
////                    }
////                }
//            }
//        }

    }

//    private void handleField(MethodAttr methodAttr, Value v, boolean isLeft) {
//        String sig = null;
//        if (v instanceof StaticFieldRef) {
//            StaticFieldRef staticFieldRef = (StaticFieldRef) v;
//            sig = staticFieldRef.getField().getSignature();
//        } else if (v instanceof InstanceFieldRef) {
//            InstanceFieldRef instanceFieldRef = (InstanceFieldRef) v;
//            sig = instanceFieldRef.getField().getSignature();
//        }
//        if (isLeft)
//            methodAttr.addWriteField(sig);
//        else methodAttr.addReadField(sig);
//    }

//    public void getStartEndNumber(Body body, MethodAttr method) {
//        int s = -1;
//        int e = -1;
////        if (body == null) return line;
//        PatchingChain<Unit> units = body.getUnits();
//        for (Unit unit : units) {
//            int l = unit.getJavaSourceStartLineNumber();
//            if (l > -1) {
//                method.setStartLinenumber(l);
//                break;
//            }
//        }
//        method.setEndLinenumber(units.getLast().getJavaSourceStartLineNumber());
//    }
}
