package symbolicExec;

import soot.*;
import soot.jimple.*;
import soot.jimple.internal.*;
import soot.toolkits.graph.Block;
import soot.toolkits.graph.BriefBlockGraph;
import soot.util.Chain;
import treeEditDistance.costmodel.NodeType;
import treeEditDistance.node.Node;
import treeEditDistance.node.PredicateNodeData;

import javax.script.ScriptException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static analyze.PatchPresentTest_new.*;

public class MethodDigest implements Serializable {
    private static final long serialVersionUID = 1L;
    private static final int STATE_FINGERPRINT_LOCAL_LIMIT = 64;
    private static final int METHOD_TRAVERSAL_NODE_BUDGET = readIntEnv("PHUNTER_DIGEST_METHOD_BUDGET_NODES", 250000);
    private static final long METHOD_TRAVERSAL_TIME_BUDGET_MS = readLongEnv("PHUNTER_DIGEST_METHOD_BUDGET_MS", 30000L);
    public transient List<List<Unit>> realUnitsPaths = new LinkedList<>();
    public List<String> realPathTailKinds = new LinkedList<>();

    public List<List<String>> realSignatures = new LinkedList<>();//Record the function signature on the path
    public List<List<String>> realVariables = new LinkedList<>();//Record the variables on the path
    public List<List<String>> LibIDPaths = new LinkedList<>();//Record the LibID's signature.
    public transient List<Unit> patchRelatedUnits;
    public List<List<Node<PredicateNodeData>>> realPredicates = new LinkedList<>();//Store the predicates on each path
    private boolean isOptimize;

    public boolean isMethodTooLarge = false;
    public transient int stateDedupPrunedCount = 0;
    private transient Set<String> visitedStateFingerprints = new HashSet<>();
    private transient long traversalStartNanos = 0L;
    private transient int traversalNodeVisits = 0;

    public MethodDigest(Body body, List<Integer> patchRelatedUnits) {
        this.patchRelatedUnits = patchRelatedUnits == null ? null
                : body.getUnits()
                .stream()
                .filter(unit -> patchRelatedUnits.contains(unit.getJavaSourceStartLineNumber()))
                .collect(Collectors.toList());
        isOptimize = true;
        enumMethodPath(body);
        checkSpecialCase(body);//if the path is empty, cancel the optimization.
    }

    public void enumMethodPath(Body body) {//Traversing paths and filtering by predicate
        visitedStateFingerprints = new HashSet<>();
        stateDedupPrunedCount = 0;
        traversalStartNanos = System.nanoTime();
        traversalNodeVisits = 0;
        BriefBlockGraph bg = new BriefBlockGraph(body);
//        modifyBlockGraph(bg, body);
        int num = bg.getBlocks().size();
        boolean[][] flags = new boolean[num][num];
        List<Block> heads = bg.getHeads();
        Block head = heads.get(0);
        List<Unit> unitPath = new ArrayList<>();
        List<String> signature = new ArrayList<>();
        List<String> variable = new ArrayList<>();
        List<String> LibIDPath = new ArrayList<>();
        List<Node<PredicateNodeData>> predicate = new ArrayList<>();
        HashMap<Value, Node<PredicateNodeData>> local = new HashMap<>();
        traverseBlock(unitPath, signature, variable, predicate, local, head, flags, LibIDPath);
    }

    private void modifyBlockGraph(BriefBlockGraph bg, Body body) {//Handling try...catch statements
        List<Block> blocks = bg.getBlocks();
        Chain<Trap> traps = body.getTraps();
        for (Trap trap : traps) {
//            Unit begin = trap.getBeginUnit();
            Unit end = trap.getEndUnit();
            Unit handler = trap.getHandlerUnit();
            //the first integer is the index of the endBlock and the second integer is the index of the handlerBlock
            int[] blockIndex = getBlockIndexOfUnit(blocks, end, handler);
            Block endBlock = blocks.get(blockIndex[0]);
            Block handlerBlock = blocks.get(blockIndex[1]);
            List<Block> preds = new ArrayList<>(handlerBlock.getPreds());
            if (!preds.contains(endBlock))
                preds.add(endBlock);
            List<Block> succs = new ArrayList<>(endBlock.getSuccs());
            if (!succs.contains(handlerBlock))
                succs.add(handlerBlock);
            endBlock.setSuccs(succs);
            handlerBlock.setPreds(preds);
        }
    }

    private int[] getBlockIndexOfUnit(List<Block> blocks, Unit end, Unit handler) {//Get the index of the block where the unit is located
        int[] index = new int[2];
        for (Block block : blocks) {
            for (Unit value : block) {
                if (value.equals(end)) {
                    index[0] = block.getIndexInMethod();
                }
                if (value.equals(handler)) {
                    index[1] = block.getIndexInMethod();
                }
            }
        }
        return index;
    }

    public void traverseBlock(List<Unit> unitPath, List<String> signature, List<String> variable,
                              List<Node<PredicateNodeData>> predicate, HashMap<Value, Node<PredicateNodeData>> local,
                              Block head, boolean[][] flags, List<String> LibIDPath) {
        if (realUnitsPaths.size() >= maxHandlePath) {// Limit the number of paths
            isMethodTooLarge = true;
            return;
        }
        if (isTraversalBudgetExceeded()) {
            markTooLargeWithFallbackPath(unitPath, signature, variable, predicate, LibIDPath);
            return;
        }
        traversalNodeVisits += 1;
        if (shouldPruneByState(head, local, predicate, LibIDPath)) {
            return;
        }
        String LibID = "";
        unitPath.addAll(getBlockUnits(head));//Add the information in the head to the list
        signature.addAll(getBlockSignatures(head));
        variable.addAll(getBlockVariable(head));
        updateLocal(local, head, LibID);
        List<Block> nextBlocks = head.getSuccs();
        if (nextBlocks.isEmpty()) {
            this.realUnitsPaths.add(unitPath);
            this.realPathTailKinds.add(pathTailKind(unitPath));
            this.realPredicates.add(predicate);
            this.realVariables.add(variable);
            this.realSignatures.add(signature);
            this.LibIDPaths.add(LibIDPath);
            return;
        }
        if (checkUnitIsPredicate(head.getTail())) {//If the block does not contain a predicate, you can save space by not saving the snapshot
            for (Block block : nextBlocks) {
                Node<PredicateNodeData> ast = getBlockPredicate(head, block, local, LibID);
                if (ast == null)
                    continue;
                if (checkCycle(head, block, flags) == 1)
                    continue;
                if (!ast.getChildren().isEmpty())
                    predicate.add(ast);
                LibIDPath.add(LibID);
                List<Unit> newUnitPath = new ArrayList<>(unitPath);
                List<String> newSignature = new ArrayList<>(signature);
                List<String> newVariable = new ArrayList<>(variable);
                List<String> newLibIDPath = new ArrayList<>(LibIDPath);
                List<Node<PredicateNodeData>> newPredicate = new ArrayList<>(predicate);
                HashMap<Value, Node<PredicateNodeData>> newLocal = new HashMap<>(local);
                traverseBlock(newUnitPath, newSignature, newVariable, newPredicate, newLocal, block, flags, newLibIDPath);
                flags[head.getIndexInMethod()][block.getIndexInMethod()] = false;
                if(!predicate.isEmpty())
                    predicate.remove(predicate.size() - 1);
            }
        } else {
            Block block = nextBlocks.get(0);
            if (checkCycle(head, block, flags) == 1)
                return;
            LibIDPath.add(LibID);
            traverseBlock(unitPath, signature, variable, predicate, local, block, flags, LibIDPath);
            flags[head.getIndexInMethod()][block.getIndexInMethod()] = false;
        }
    }

    public List<Unit> getBlockUnits(Block block) {
        List<Unit> paths = new ArrayList<>();
        for (Unit unit : block) {
            paths.add(unit);
        }
        return paths;
    }

    public List<String> getBlockSignatures(Block block) {
        List<String> signature = new ArrayList<>();
        for (Unit unit : block) {
            Stmt stmt = (Stmt) unit;
            if (stmt.containsInvokeExpr()) {
                SootMethod method = stmt.getInvokeExpr().getMethod();
                if (method.isStatic())
                    signature.add(method.getDeclaringClass().getName() + ",static," + getParamForm(method));
                else signature.add(method.getDeclaringClass().getName() + "," + getParamForm(method));
            }
        }
        return signature;
    }

    public List<String> getBlockVariable(Block block) {
        List<String> variable = new ArrayList<>();
        for (Unit unit : block) {
            Stmt stmt = (Stmt) unit;
            if (stmt.containsFieldRef()) {
                try {
                    SootField field = stmt.getFieldRef().getField();
                    if (field == null || field.getDeclaringClass() == null || field.getType() == null) {
                        variable.add("java.lang.Object,java.lang.Object,");
                    } else {
                        variable.add(field.getDeclaringClass().getName() + "," + field.getType() + ",");
                    }
                } catch (RuntimeException ex) {
                    variable.add("java.lang.Object,java.lang.Object,");
                }
            } else if (stmt.containsArrayRef()) {
                try {
                    ArrayRef arrayRef = stmt.getArrayRef();
                    if (arrayRef == null || arrayRef.getType() == null) {
                        variable.add("java.lang.Object,");
                    } else {
                        variable.add(arrayRef.getType().getArrayType().toString() + ",");
                    }
                } catch (RuntimeException ex) {
                    variable.add("java.lang.Object,");
                }
            }
        }
        return variable;
    }

    public void updateLocal(HashMap<Value, Node<PredicateNodeData>> local, Block block, String LibID) {
        for (Unit unit : block) {
            if (unit instanceof AssignStmt) {
                AssignStmt assignStmt = (AssignStmt) unit;
                Value left = assignStmt.getLeftOp();
                Value right = assignStmt.getRightOp();
                if (right instanceof InvokeExpr) {
                    //Handle the case when assignStmt contains invokeExpr, when the parameters of the call need to be extracted as well.
                    InvokeExpr expr = (InvokeExpr) right;
                    SootMethod method = expr.getMethod();
                    if (method.getSignature().contains("void <init>()")) {
                        LibID += "M";
                    } else {
                        LibID += "N";
                    }
                    List<Value> values = expr.getArgs();
                    Node<PredicateNodeData> rightNode;
                    if (expr instanceof StaticInvokeExpr) {
                        PredicateNodeData data = new PredicateNodeData(NodeType.Invoke,
                                method.getDeclaringClass().getName() + ",static," + getParamForm(method));
                        rightNode = new Node<>(data);
                        for (Value value : values) {
                            rightNode.addChild(value);
                        }
                    } else if (expr instanceof DynamicInvokeExpr) {
                        DynamicInvokeExpr dExpr = (DynamicInvokeExpr) expr;
                        PredicateNodeData data = new PredicateNodeData(NodeType.Invoke,
                                method.getDeclaringClass().getName() + ",dynamic," + getParamForm(method));
                        rightNode = new Node<>(data);
                        List<Value> bsa = dExpr.getBootstrapArgs();
                        for (Value value : bsa) {
                            rightNode.addChild(value);
                        }
                        for (Value value : values) {
                            rightNode.addChild(value);
                        }
                    } else {
                        Value caller = ((InstanceInvokeExpr) expr).getBase();
                        PredicateNodeData data = new PredicateNodeData(NodeType.Invoke,
                                method.getDeclaringClass().getName() + "," + getParamForm(method));
                        rightNode = new Node<>(data);
                        rightNode.addChild(caller);
                        for (Value value : values) {
                            rightNode.addChild(value);
                        }
                    }
                    rightNode.traverse(rightNode, local);
                    local.put(left, rightNode);
                } else if (right instanceof BinopExpr) {
                    BinopExpr expr = (BinopExpr) right;
                    String symbol = expr.getSymbol().trim();
                    if (checkSymbolToOptimize(symbol, expr, block.getPredOf(unit))) {
                        PredicateNodeData data = new PredicateNodeData(IntConstant.v(0));
                        Node<PredicateNodeData> rightNode = new Node<>(data);
                        local.put(left, rightNode);
                    } else {
                        PredicateNodeData data = new PredicateNodeData(NodeType.BinOperators, symbol);
                        Node<PredicateNodeData> rightNode = new Node<>(data);
                        rightNode.addChild(expr.getOp1());
                        rightNode.addChild(expr.getOp2());
                        rightNode.traverse(rightNode, local);
                        local.put(left, rightNode);
                    }
                } else if (right instanceof JCastExpr) {
                    JCastExpr expr = (JCastExpr) right;
                    Type type = expr.getCastType();
                    PredicateNodeData data;
                    Node<PredicateNodeData> rightNode;
                    if (expr.getOp() instanceof Constant) {
                        Constant c = (Constant) expr.getOp();
                        data = new PredicateNodeData(c);
                    } else {
                        Local afterCast = (Local) expr.getOp();
                        afterCast.setType(type);
                        data = new PredicateNodeData(afterCast);
                    }
                    rightNode = new Node<>(data);
                    rightNode.traverse(rightNode, local);
                    local.put(left, rightNode);
                } else if (right instanceof UnopExpr) {
                    UnopExpr expr = (UnopExpr) right;
                    Value v = expr.getOp();
                    PredicateNodeData data;
                    if (expr instanceof LengthExpr) {
                        data = new PredicateNodeData(NodeType.UnaryOperators, "Length");
                    } else {
                        data = new PredicateNodeData(NodeType.UnaryOperators, "Negative");
                    }
                    Node<PredicateNodeData> rightNode = new Node<>(data);
                    rightNode.addChild(v);
                    rightNode.traverse(rightNode, local);
                    local.put(left, rightNode);
                } else if (right instanceof AnyNewExpr) {
                    PredicateNodeData data;
                    Node<PredicateNodeData> rightNode;
                    if (right instanceof NewExpr) {
                        NewExpr expr = (NewExpr) right;
                        data = new PredicateNodeData(NodeType.Class, expr.getType().toString());
                        rightNode = new Node<>(data);
                    } else if (right instanceof NewMultiArrayExpr) {
                        NewMultiArrayExpr expr = (NewMultiArrayExpr) right;
                        data = new PredicateNodeData(NodeType.MultiArray, expr.getType().toString());
                        rightNode = new Node<>(data);
                        for (Value val : expr.getSizes()) {
                            rightNode.addChild(val);
                        }
                    } else {//expr instanceof NewArrayExpr
                        NewArrayExpr expr = (NewArrayExpr) right;
                        data = new PredicateNodeData(NodeType.Array, expr.getBaseType().toString());
                        Value v = expr.getSize();//record the new array's length
                        rightNode = new Node<>(data);
                        rightNode.addChild(v);
                    }
                    rightNode.traverse(rightNode, local);
                    local.put(left, rightNode);
                } else if (right instanceof ArrayRef) {
                    ArrayRef ar = (ArrayRef) right;
                    PredicateNodeData data;
                    try {
                        data = new PredicateNodeData(NodeType.Array, ar.getType().toString());
                    } catch (RuntimeException ex) {
                        data = new PredicateNodeData(NodeType.Array, "java.lang.Object");
                    }
                    Value index = ar.getIndex();
                    Node<PredicateNodeData> rightNode = new Node<>(data);
                    rightNode.addChild(index);
                    rightNode.traverse(rightNode, local);
                    local.put(left, rightNode);
                } else if (right instanceof InstanceOfExpr) {
                    InstanceOfExpr expr = (InstanceOfExpr) right;
                    Type type = expr.getCheckType();
                    String clazz;
                    if (type instanceof ArrayType)
                        clazz = ((ArrayType) type).baseType.toString();
                    else clazz = type.toString();
                    PredicateNodeData data = new PredicateNodeData(NodeType.InstanceOf, clazz);
                    Value v = expr.getOp();
                    Node<PredicateNodeData> rightNode = new Node<>(data);
                    rightNode.addChild(v);
                    rightNode.traverse(rightNode, local);
                    local.put(left, rightNode);
                } else {//The right-hand side is an immediate number or object
                    PredicateNodeData data = new PredicateNodeData(right);
                    Node<PredicateNodeData> rightNode = new Node<>(data);
                    rightNode.traverse(rightNode, local);
                    local.put(left, rightNode);
                }
            } else if (unit instanceof IdentityStmt) {
                IdentityStmt identityStmt = (IdentityStmt) unit;
                Value left = identityStmt.getLeftOp();
                Value right = identityStmt.getRightOp();
                PredicateNodeData data = new PredicateNodeData(right);
                Node<PredicateNodeData> rightNode = new Node<>(data);
                rightNode.traverse(rightNode, local);
                local.put(left, rightNode);
            }
            List<ValueBox> defs = unit.getDefBoxes();
            for (ValueBox def : defs) {
                if (def.getValue() instanceof FieldRef) {
                    LibID += "H";
                }
            }
            List<ValueBox> uses = unit.getUseBoxes();
            for (ValueBox use : uses) {
                if (use.getValue() instanceof StringConstant) {
                    LibID += "S";
                } else if (use.getValue() instanceof FieldRef) {
                    LibID += "F";
                }
            }
        }
    }

    private boolean checkValidIfStmt(IfStmt ifStmt,Unit nextStmt){
        Stmt target = ifStmt.getTarget();
        if(target instanceof GotoStmt && nextStmt instanceof GotoStmt){
            Unit t1 = ((GotoStmt) nextStmt).getTarget();
            Unit t2 = ((GotoStmt) target).getTarget();
            if (t2 instanceof GotoStmt){
                Unit t3 = ((GotoStmt) t2).getTarget();
                return t1 != t3;
            }
        }
        return true;
    }

    public Node<PredicateNodeData> getBlockPredicate(Block block, Block nextBlock, HashMap<Value, Node<PredicateNodeData>> local, String LibID) {//Get the predicate in the block and update the predicate
        Unit unit = block.getTail();
        Unit nextUnit = nextBlock.getHead();
        if (unit instanceof IfStmt) {
            ConditionExpr condition = (ConditionExpr) ((IfStmt) unit).getCondition();
            Stmt target = ((IfStmt) unit).getTarget();
            Stmt nextStmt = (Stmt) nextUnit;
            String symbol = condition.getSymbol().trim();
            Value left = condition.getOp1();
            Value right = condition.getOp2();
            if (symbol.equals(">=")) {
                Value tmp = left;
                left = right;
                right = tmp;
                symbol = "<=";
            } else if (symbol.equals(">")) {
                Value tmp = left;
                left = right;
                right = tmp;
                symbol = "<";
            }
            PredicateNodeData data = new PredicateNodeData(NodeType.Comparator, symbol);
            Node<PredicateNodeData> node = new Node<>(data);
            if(!checkValidIfStmt((IfStmt)unit,block.getBody().getUnits().getSuccOf(unit)))
                return node;
            node.addChild(left);
            node.addChild(right);
            node.traverse(node, local);// update the variable of the predicate
            if (!checkBranch(node, target, nextStmt))
                return null;
            return node;
        } else if (unit instanceof JTableSwitchStmt) {
            JTableSwitchStmt table = (JTableSwitchStmt) unit;
            Stmt nextStmt = (Stmt) nextUnit;
            Value key = table.getKey();
            int low = table.getLowIndex();
            int high = table.getHighIndex();
            for (int i = low; i < high; i++) {
                if (table.getTarget(i - low) == nextStmt) {
                    PredicateNodeData data = new PredicateNodeData(NodeType.Comparator, "==");
                    Node<PredicateNodeData> node = new Node<>(data);
                    node.addChild(key);
                    node.addChild(IntConstant.v(i));
                    node.traverse(node, local);
                    if (optimizePredicate(node) == 0)
                        return null;
                    return node;
                }
            }
            if (table.getDefaultTarget() == nextStmt) {
                Value DEFAULT = IntConstant.v(Integer.MAX_VALUE);
                PredicateNodeData data = new PredicateNodeData(NodeType.Comparator, "==");
                Node<PredicateNodeData> node = new Node<>(data);
                node.addChild(key);
                node.addChild(DEFAULT);
                node.traverse(node, local);
                return node;
            }
        } else if (unit instanceof JLookupSwitchStmt) {
            JLookupSwitchStmt look = (JLookupSwitchStmt) unit;
            Stmt nextStmt = (Stmt) nextUnit;
            Value key = look.getKey();
            List<IntConstant> caseList = look.getLookupValues();
            for (int i = 0; i < caseList.toArray().length; i++) {
                if (look.getTarget(i) == nextStmt) {
                    PredicateNodeData data = new PredicateNodeData(NodeType.Comparator, "==");
                    Node<PredicateNodeData> node = new Node<>(data);
                    node.addChild(key);
                    node.addChild(caseList.get(i));
                    node.traverse(node, local);
                    if (optimizePredicate(node) == 0)
                        return null;
                    return node;
                }
            }
            if (look.getDefaultTarget() == nextStmt) {
                Value DEFAULT = IntConstant.v(Integer.MAX_VALUE);
                PredicateNodeData data = new PredicateNodeData(NodeType.Comparator, "==");
                Node<PredicateNodeData> node = new Node<>(data);
                node.addChild(key);
                node.addChild(DEFAULT);
                node.traverse(node, local);
                return node;
            }
        } else if (unit instanceof JReturnStmt) {
            LibID += "R";
        } else if (unit instanceof JGotoStmt) {
            LibID += "G";
        }
        return null;
    }

    public boolean checkBranch(Node<PredicateNodeData> ast, Stmt target, Stmt nextStmt) {//Determine if the predicate matches the target path
        int result = optimizePredicate(ast);
        if (result == -1)
            return true;
        else if (result == 0 && !target.equals(nextStmt))
            return true;
        else return result == 1 && target.equals(nextStmt);
    }

    public int checkCycle(Block head, Block nextBlock, boolean[][] flags) {//Determine if the loop needs to be terminated
        int headIndex = head.getIndexInMethod();
        int nextIndex = nextBlock.getIndexInMethod();
        if (flags[headIndex][nextIndex])
            return 1;
        flags[headIndex][nextIndex] = true;
        return 0;
    }

    public boolean checkUnitIsPredicate(Unit unit) {
        return unit instanceof IfStmt || unit instanceof JLookupSwitchStmt || unit instanceof JTableSwitchStmt;
    }

    private boolean checkSymbolToOptimize(String symbol, BinopExpr expr, Unit prevUnit) {
        if (symbol.equals("%")) {
            if (prevUnit instanceof AssignStmt) {
                AssignStmt stmt = (AssignStmt) prevUnit;
                Value left = stmt.getLeftOp();
                if (stmt.getRightOp() instanceof BinopExpr) {
                    BinopExpr right = (BinopExpr) stmt.getRightOp();
                    if (right.getSymbol().trim().equals("*")) {
                        if (left == expr.getOp1()) {
                            return expr.getOp2().equals(right.getOp1()) || expr.getOp2().equals(right.getOp2());
                        } else if (left == expr.getOp2()) {
                            return expr.getOp1().equals(right.getOp1()) || expr.getOp1().equals(right.getOp2());
                        }
                    }
                }
            }
        }
        return false;
    }

    private String getParamForm(SootMethod method) {
        StringBuilder sb = new StringBuilder();
        Type ret = method.getReturnType();
        if (ret instanceof RefType)
            sb.append(ret).append(",");
        else if (ret instanceof ArrayType)
            sb.append(((ArrayType) ret).baseType).append(","); // ignore array
        else sb.append(ret).append(",");

        for (Type t : method.getParameterTypes()) {
            if (t instanceof RefType)
                sb.append(t).append(",");
            else if (t instanceof ArrayType)
                sb.append(((ArrayType) t).baseType).append(","); // ignore array
            else sb.append(t).append(",");
        }
        return sb.toString();
    }

    private int optimizePredicate(Node<PredicateNodeData> ast) {
        if (!isOptimize)
            return -1;
        if (sePy == null || seJs == null) {
            return -1;
        }
        String str = ast.extractNodeData(ast);
        try {
            Object evalResult;
            if (str.contains("^") || str.contains("|") || str.contains("&")) {// Determine if it contains bitwise operations
                evalResult = sePy.eval(str);
            } else {
                evalResult = seJs.eval(str);
            }
            Boolean result = toBoolean(evalResult);
            if (result == null) {
                return -1;
            }
            if (result)
                return 1;
            else
                return 0;
        } catch (ScriptException ignored) {
            return -1;
        } catch (RuntimeException ignored) {
            return -1;
        }
    }

    private Boolean toBoolean(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof Boolean) {
            return (Boolean) value;
        }
        if (value instanceof Number) {
            return ((Number) value).doubleValue() != 0.0;
        }
        String text = value.toString();
        if (text == null) {
            return null;
        }
        text = text.trim();
        if (text.equalsIgnoreCase("true")) {
            return true;
        }
        if (text.equalsIgnoreCase("false")) {
            return false;
        }
        return null;
    }

    public int getPathCount() {
        return realPathTailKinds == null ? 0 : realPathTailKinds.size();
    }

    public String getPathTailKind(int index) {
        if (realPathTailKinds == null || index < 0 || index >= realPathTailKinds.size()) {
            return "OTHER";
        }
        return realPathTailKinds.get(index);
    }

    public static boolean isTailKindCompatible(String left, String right) {
        return left != null && left.equals(right)
                && ("RETURN".equals(left) || "RETURN_VOID".equals(left) || "THROW".equals(left));
    }

    public void prepareForSerialization() {
        if (realPredicates != null) {
            for (List<Node<PredicateNodeData>> predicates : realPredicates) {
                for (Node<PredicateNodeData> predicate : predicates) {
                    normalizePredicateNode(predicate);
                }
            }
        }
        patchRelatedUnits = null;
    }

    private void normalizePredicateNode(Node<PredicateNodeData> node) {
        if (node == null) {
            return;
        }
        PredicateNodeData data = node.getNodeData();
        if (data != null && data.getNodeType() == null) {
            data.setNodeType(NodeType.Parameter);
            data.setData("UNK");
            data.setValue(null);
        }
        for (Node<PredicateNodeData> child : node.getChildren()) {
            normalizePredicateNode(child);
        }
    }

    private String pathTailKind(List<Unit> unitPath) {
        if (unitPath == null || unitPath.isEmpty()) {
            return "OTHER";
        }
        Unit tail = unitPath.get(unitPath.size() - 1);
        if (tail instanceof ReturnStmt) {
            return "RETURN";
        }
        if (tail instanceof ReturnVoidStmt) {
            return "RETURN_VOID";
        }
        if (tail instanceof ThrowStmt) {
            return "THROW";
        }
        return "OTHER";
    }

    public void checkSpecialCase(Body body) {
        if (realUnitsPaths != null && realUnitsPaths.size() == 0) {
            isOptimize = false;
            enumMethodPath(body);
        }
    }

    private boolean shouldPruneByState(
            Block head,
            HashMap<Value, Node<PredicateNodeData>> local,
            List<Node<PredicateNodeData>> predicate,
            List<String> libIDPath
    ) {
        if (visitedStateFingerprints == null) {
            visitedStateFingerprints = new HashSet<>();
        }
        String key = buildStateFingerprint(head, local, predicate, libIDPath);
        if (!visitedStateFingerprints.add(key)) {
            stateDedupPrunedCount += 1;
            return true;
        }
        return false;
    }

    private String buildStateFingerprint(
            Block head,
            HashMap<Value, Node<PredicateNodeData>> local,
            List<Node<PredicateNodeData>> predicate,
            List<String> libIDPath
    ) {
        int blockId = head.getIndexInMethod();
        int localSumHash = 1;
        int localXorHash = 0;
        int localCount = 0;
        if (local != null && !local.isEmpty()) {
            for (HashMap.Entry<Value, Node<PredicateNodeData>> entry : local.entrySet()) {
                int entryHash = entryFingerprint(entry);
                localSumHash += entryHash;
                localXorHash ^= Integer.rotateLeft(entryHash, 7);
                localCount += 1;
                if (localCount >= STATE_FINGERPRINT_LOCAL_LIMIT) {
                    break;
                }
            }
        }

        int predicateHash = 1;
        int predicateSize = predicate == null ? 0 : predicate.size();
        if (predicateSize > 0) {
            Node<PredicateNodeData> tail = predicate.get(predicateSize - 1);
            predicateHash = shallowNodeFingerprint(tail);
        }

        int libTailHash = 0;
        int libPathSize = libIDPath == null ? 0 : libIDPath.size();
        if (libPathSize > 0) {
            String tail = libIDPath.get(libPathSize - 1);
            libTailHash = tail == null ? 0 : tail.hashCode();
        }

        return blockId
                + "|lc=" + localCount
                + "|lhs=" + localSumHash
                + "|lhx=" + localXorHash
                + "|ps=" + predicateSize
                + "|ph=" + predicateHash
                + "|ls=" + libPathSize
                + "|lt=" + libTailHash;
    }

    private int entryFingerprint(HashMap.Entry<Value, Node<PredicateNodeData>> entry) {
        Value key = entry.getKey();
        Node<PredicateNodeData> value = entry.getValue();
        int hash = 17;
        if (key != null) {
            hash = 31 * hash + key.getClass().getName().hashCode();
            hash = 31 * hash + key.toString().hashCode();
        }
        hash = 31 * hash + shallowNodeFingerprint(value);
        return hash;
    }

    private int shallowNodeFingerprint(Node<PredicateNodeData> node) {
        if (node == null) {
            return 0;
        }
        int hash = 13;
        PredicateNodeData data = node.getNodeData();
        if (data != null) {
            NodeType nodeType = data.getNodeType();
            if (nodeType != null) {
                hash = 31 * hash + nodeType.name().hashCode();
            }
            String payload = data.getData();
            if (payload != null) {
                hash = 31 * hash + payload.hashCode();
            }
            Value value = data.getValue();
            if (value != null) {
                hash = 31 * hash + value.toString().hashCode();
            }
        }
        hash = 31 * hash + node.getChildren().size();
        return hash;
    }

    private boolean isTraversalBudgetExceeded() {
        if (METHOD_TRAVERSAL_NODE_BUDGET > 0 && traversalNodeVisits >= METHOD_TRAVERSAL_NODE_BUDGET) {
            return true;
        }
        if (METHOD_TRAVERSAL_TIME_BUDGET_MS > 0 && traversalStartNanos > 0L) {
            long elapsedMs = (System.nanoTime() - traversalStartNanos) / 1_000_000L;
            return elapsedMs >= METHOD_TRAVERSAL_TIME_BUDGET_MS;
        }
        return false;
    }

    private void markTooLargeWithFallbackPath(
            List<Unit> unitPath,
            List<String> signature,
            List<String> variable,
            List<Node<PredicateNodeData>> predicate,
            List<String> libIDPath
    ) {
        isMethodTooLarge = true;
        if (realUnitsPaths.isEmpty() && unitPath != null && !unitPath.isEmpty()) {
            realUnitsPaths.add(new ArrayList<>(unitPath));
            realPathTailKinds.add(pathTailKind(unitPath));
            realPredicates.add(predicate == null ? new ArrayList<>() : new ArrayList<>(predicate));
            realVariables.add(variable == null ? new ArrayList<>() : new ArrayList<>(variable));
            realSignatures.add(signature == null ? new ArrayList<>() : new ArrayList<>(signature));
            LibIDPaths.add(libIDPath == null ? new ArrayList<>() : new ArrayList<>(libIDPath));
        }
    }

    private static int readIntEnv(String key, int fallback) {
        try {
            String value = System.getenv(key);
            if (value == null || value.trim().isEmpty()) {
                return fallback;
            }
            return Integer.parseInt(value.trim());
        } catch (RuntimeException ex) {
            return fallback;
        }
    }

    private static long readLongEnv(String key, long fallback) {
        try {
            String value = System.getenv(key);
            if (value == null || value.trim().isEmpty()) {
                return fallback;
            }
            return Long.parseLong(value.trim());
        } catch (RuntimeException ex) {
            return fallback;
        }
    }
}
