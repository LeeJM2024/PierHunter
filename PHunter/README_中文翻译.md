# PHunter

这是论文 **“Precise and Efficient Patch Presence Test for Android Applications against Code Obfuscation”** 的代码仓库。

该项目介绍了 PHunter：一个面向 Android 应用、能够对抗代码混淆的**精确且高效的补丁存在性检测工具**。它支持识别多种混淆场景，包括：

- 标识符重命名（identifier renaming）
- 包扁平化（package flattening）
- 控制流随机化（control flow randomization）
- 死代码删除（dead code removal）

与其他工具相比，PHunter **不依赖调试信息**，而是利用**细粒度的抗混淆语义信息**来判断补丁状态。

## 数据集结构

```text
dataset                
├── apps_all_option          # 包含使用“全部混淆选项”处理后的 APK
│   ├── origin               # 未混淆的 APK
│   ├── proguard-apk         # 使用 Proguard 混淆的 APK
│   ├── dasho-apk            # 使用 Dasho 混淆的 APK
│   ├── allatori-apk         # 使用 Allatori 混淆的 APK
│   ├── obfuscapk-apk        # 使用 Obfuscapk 混淆的 APK
│   ├── origin_GT.txt        # origin、Allatori、Obfuscapk 对应的 groundtruth
│   ├── proguard_GT.txt      # Proguard 对应的 groundtruth
│   └── dasho_GT.txt         # Dasho 对应的 groundtruth
├── apps_one_option          # 包含使用“单一混淆选项”处理后的 APK
│   │   ├── controlflow      # 使用控制流混淆（Control Flow Obfuscation）的 APK
│   │   ├── rename           # 使用标识符重命名（Identifier Renaming）的 APK
│   │   ├── remove           # 使用代码裁剪（Code Shrinking）的 APK
│   │   ├── flatten          # 使用包扁平化（Package Flattening）的 APK
│   │   ├── origin_GT2.txt   # controlflow、rename、flatten 对应的 groundtruth
│   │   └── remove_GT.txt    # remove 对应的 groundtruth
└── CVEs
    ├── CVE-2018-1324
    │   ├── commons-compress-CVE-2018-1324-pre.jar                        # 打补丁前版本
    │   ├── commons-compress-CVE-2018-1324-post.jar                       # 打补丁后版本
    │   ├── CVE-2018-1324_2a2f1dc48e22a34ddb72321a4db211da91aa933b.diff   # 补丁文件
    ├── ...
```

该数据集包含实验中使用的全部 APK 文件（包括混淆版与未混淆版）、groundtruth 文件，以及与漏洞相关的文件（补丁前/补丁后参考库与补丁文件）。

在生成 groundtruth 文件时，我们首先解析 Gradle 构建文件，识别每个应用使用的所有第三方库，然后通过查询 NVD 收集每个库已报告的漏洞及其对应的受影响版本。

例如，对于 [`origin_GT.txt`](dataset/apps_all_option/origin_GT.txt) 中的一行：

`de.vier_bier.habpanelviewer.apk:CVE-2021-0341:True`

它表示该 APK 使用了某个第三方库（TPL），且该 TPL 受 CVE-2021-0341 影响；其中 `True` 表示**补丁不存在**。

对于某些混淆器，它们会删除未使用代码以缩小 APK 体积，而与补丁相关的方法也可能在混淆过程中被删除。因此，我们参考映射文件（记录混淆前后的类名/方法名）。如果补丁相关方法被移除，我们会相应更新 groundtruth。  
[`proguard_GT.txt`](dataset/apps_all_option/proguard_GT.txt)、[`dasho_GT.txt`](dataset/apps_all_option/dasho_GT.txt) 和 [`remove_GT.txt`](dataset/apps_one_option/remove_GT.txt) 就是通过这种方式生成的。

## Artifact 使用方式

可直接使用的产物是 [PHunter.jar](PHunter.jar)，其所需依赖已经全部包含在内。  
带有 groundtruth 的采样数据集位于文件夹：[samples](./samples)。

你也可以使用 Maven 构建源码。  
注意：当前 Java 版本应为 **8 或 11**，若使用 **Java 17** 会遇到 `NullPointerException`。  
构建后的产物位于：

`target/PHunter-1.1-jar-with-dependencies.jar`

```bash
$ mvn clean compile assembly:single
```

要使用 PHunter，用户需要准备以下内容：

- 补丁前第三方库（`.jar` / `.aar`）
- 补丁后第三方库（`.jar` / `.aar`）
- 补丁文件（`.diff`）
- 待检测应用（`.apk`）

仓库中提供了一个 [sample](./sample)，用于说明 PHunter 的使用方式。

```bash
$ java -jar PHunter.jar --help
usage: help [-output <arg>] [-preTPL <arg>] [-enableDebug] [-postTPL <arg>] [-targetAPK <arg>]
       [-patchFiles <arg>] [-androidJar <arg>] [-threadNum <arg>] [-?]

-targetAPK <arg>    Path to pre-patched binary(.apk), or a directory contains multi apks
-preTPL <arg>       Path to pre-patched binary(.jar/.aar)
-postTPL <arg>      Path to post-patched binary(.jar/.aar)
-?,--help           Print this help message
-androidJar <arg>   The path to android.jar
-enableDebug        Is enable debug level
-patchFiles <arg>   Path to patch files, if exist more than 1 files, split by the ';' (e.g., "1.diff;2.diff")
-threadNum <arg>    The number of threads to use
```

上面参数说明翻译如下：

- `-targetAPK <arg>`：待检测的 APK 路径，或包含多个 APK 的目录
- `-preTPL <arg>`：补丁前第三方库（`.jar/.aar`）路径
- `-postTPL <arg>`：补丁后第三方库（`.jar/.aar`）路径
- `-?, --help`：打印帮助信息
- `-androidJar <arg>`：`android.jar` 的路径
- `-enableDebug`：是否开启 debug 级别日志
- `-patchFiles <arg>`：补丁文件路径；若有多个文件，用 `;` 分隔（例如 `"1.diff;2.diff"`）
- `-threadNum <arg>`：使用的线程数

### 示例

```bash
$ java -jar ./PHunter.jar --preTPL sample/commons-compress-CVE-2018-1324-pre.jar --postTPL sample/commons-compress-CVE-2018-1324-post.jar --threadNum 10 --androidJar ./android-31/android.jar --patchFiles sample/CVE-2018-1324_2a2f1dc48e22a34ddb72321a4db211da91aa933b.diff --targetAPK sample/com.greenaddress.abcore.apk
```
```bash
$ java -jar ./PHunter.jar \
  --preTPL real-sample/CVE-2023-33202/bcprov-jdkon-CVE-2023-33202-pre.jar \
  --postTPL real-sample/CVE-2023-33202/bcprov-jdkon-CVE-2023-33202-post.jar \
  --threadNum 10 \
  --androidJar ./android-31/android.jar \
  --patchFiles real-sample/CVE-2023-33202/CVE-2023-33202_43dcc12ddf.diff \
  --targetAPK real-sample/atalk.apk
```
```bash
$ java -jar ./PHunter.jar \
  --preTPL real-sample/CVE-2021-42550/logback-core-CVE-2021-42550-pre.jar \
  --postTPL real-sample/CVE-2021-42550/logback-core-CVE-2021-42550-post.jar \
  --threadNum 10 \
  --androidJar ./android-31/android.jar \
  --patchFiles real-sample/CVE-2021-42550/CVE-2021-42550_171105ded9.diff \
  --targetAPK real-sample/newpipe.apk
```

终端输出如下，表示该目标应用中**存在该 CVE 补丁**：

```text
[main] INFO analyze.BinaryAnalyzer - Analyzing the pre-patched binary sample/commons-compress-CVE-2018-1324-pre.jar
Soot started on Fri Nov 18 01:08:28 CST 2022
Soot finished on Fri Nov 18 01:08:43 CST 2022
Soot has run for 0 min. 15 sec.
[main] INFO analyze.BinaryAnalyzer - Analyzing the post-patched binary sample/commons-compress-CVE-2018-1324-post.jar
Soot started on Fri Nov 18 01:08:44 CST 2022
Soot finished on Fri Nov 18 01:08:58 CST 2022
Soot has run for 0 min. 14 sec.
[main] INFO analyze.ParsePatchFiles - Analyzing the patch sample/CVE-2018-1324_2a2f1dc48e22a34ddb72321a4db211da91aa933b.diff
[main] INFO analyze.APKAnalyzer - Analyzing the apk sample/com.greenaddress.abcore.apk
Soot started on Fri Nov 18 01:08:59 CST 2022
Soot finished on Fri Nov 18 01:09:06 CST 2022
Soot has run for 0 min. 7 sec.
patch-related method count = 1
[main] INFO analyze.PatchPresentTest_new - The matched pairs for pre-patch TPL and APP are:
[main] INFO analyze.PatchPresentTest_new - <org.apache.commons.compress.archivers.zip.X0017_StrongEncryptionHeader: void parseCentralDirectoryFormat(byte[],int,int)>   <org.apache.commonsmpress.archiv.coers.zip.X0017_StrongEncryptionHeader: void parseCentralDirectoryFormat(byte[],int,int)>      0.843125
[main] INFO analyze.PatchPresentTest_new - The matched pairs for post-patch TPL and APP are:
[main] INFO analyze.PatchPresentTest_new - <org.apache.commons.compress.archivers.zip.X0017_StrongEncryptionHeader: void parseCentralDirectoryFormat(byte[],int,int)>   <org.apache.commons.compress.archivers.zip.X0017_StrongEncryptionHeader: void parseCentralDirectoryFormat(byte[],int,int)>      0.888264
[main] INFO analyze.PatchPresentTest_new - the patch IS PRESENT, pre similarity=0.843125        post similarity=0.888264
```

PHunter 报告补丁存在。接着查看 groundtruth 文件 [`origin_GT.txt`](dataset/apps_all_option/origin_GT.txt)，可以找到如下这一行：

```text
com.greenaddress.abcore.apk:CVE-2018-1324:False
```

这表示该 APK **不受** CVE-2018-1324 影响，因此该结果是一个**真正例（true positive）**。

## 补充信息

### **树结构（Tree Structure）**

基于 Jimple 的巴科斯-诺尔范式（Backus-Naur Form, BNF），我们在工具中定义了树结构的 `ExprType` 和 `Data`。

| ExprType        | Data                                 | Children                                                            | Example |
|-----------------|--------------------------------------|---------------------------------------------------------------------|---------|
| Comparator      | 比较符号                              | 两个树节点，分别表示左右操作数                                       | `>`, `>=`, `==`, `!=` 等 |
| BinOperator     | 二元运算符                            | 两个树节点，分别表示左右操作数                                       | `+`, `-`, `*`, `/` 等 |
| UnaryOperator   | 一元运算符                            | 一个树节点，表示操作数                                               | `lengthof`，`-`（负号） |
| InstanceOf      | 具体类名                              | 一个树节点，表示实例                                                 | 假设语句是 `v instanceof MyClass`，则其 Data 是 `MyClass` |
| Invoke          | 返回类型和参数类型                    | 若干树节点，表示各个参数变量                                         | 假设调用框架函数 `boolean startsWith(String a)`，则其 Data 是 `boolean,String` |
| Array           | 数组的基础类型                        | 一个树节点，表示数组大小                                             | 若新建一个基础类型为 `long` 的数组，其 Data 形式为 `long` |
| Constant        | 带值的常量类型                        | -                                                                   | 假设一个值为 15 的 `long` 常量，其 Data 记为 `long#15` |
| Class           | 类名                                  | -                                                                   | `MyClass` |
| Parameter       | 目标方法参数的索引                    | -                                                                   | 假设目标方法原型为 `public void fun(MyClass p1, int p2)`，则 `p1` 为 `1`，`p2` 为 `2` |
| Field           | 声明类 + 类型                         | -                                                                   | 假设 `MyClass.java` 中声明了一个 `long` 类型字段，则其 Data 形式为 `MyClass#long` |
| CaughtException | 一个唯一字符串，用于表示捕获的异常     | -                                                                   | `@caughtexception` |

<!-- |MultiArray|多维数组的类型|若干树节点，表示每一维的大小|假设语句为 "a[0] = new int[3][3]"，则其 Data 为 "int[][]"| -->

### **混淆策略（Obfuscation Strategies）**

- `Code Shrinking`：删除未使用代码，以减小程序体积。
- `Package Flattening`：打破原有代码层级结构，把多个包中的类重新打包到同一个包中。
- `Identifier Renaming`：重命名包、类、方法和变量。例如，把标识符改成 `x`、`y` 这类无意义字符。
- `Control Flow Obfuscation`：通过插入冗余控制流、变量和函数调用来修改原始控制流图（CFG），在保持原语义不变的情况下显著增加逆向分析难度。
- `String Encryption`：将代码中出现的字符串加密成无意义字符串，用于保护代码中的敏感信息，例如密钥、邮箱地址等。

### BinXray 的重新实现

[BinXray](https://sites.google.com/view/submission-for-issta-2020) 最初是为 C/C++ 设计并使用 Python 实现的。  
幸运的是，我们可以复用 BinXray 的主体代码；两者主要只在预处理阶段（即提取二进制指令）有所不同，其余代码基本可以直接复用。

具体来说，我们首先使用 [dx](https://developer.android.com/studio/releases/platform-tools) 将 TPL 从 `.jar` 转换为 `.dex`。随后使用 [Androguard](https://github.com/androguard/androguard) 从 TPL（`.dex`）和应用（`.apk`）中提取 Dalvik 指令。

在 BinXray 的设计中，预处理阶段需要对每条汇编指令进行规范化（例如，把间接的 `memory access` 替换为符号项 `mem`）。但 Dalvik 字节码中并不存在这种 `memory access`。因此，我们只提取每条 Dalvik 指令的 opcode，例如 `invoke-direct`。这一思路与 ATVHunter 相同：它同样从 Dalvik 指令中提取 opcode 来构建方法签名。

重新实现后的 BinXray 在未混淆应用上取得了很好的结果（见论文 Table 3），这说明我们的实现是有效的。

### **TPL 信息**

我们从 F-Droid（一个开源 Android 应用仓库）中抓取了 4,561 个开源应用。通过解析 Gradle 构建文件，我们识别出每个应用使用的所有库，然后通过查询 NVD 收集每个库已报告的漏洞及其对应受影响版本。  
最终，经过大量人工整理，我们收集到了 **94 个 CVE**，它们影响 **31 类不同的常见库**（其中 `org.eclipse.jetty:jetty-X` 被算作同一类库，因此总 TPL 数为 31）。

本文中选取的 CVE 如下表所示。

| library (group:artifact)                    | CVE |
|---------------------------------------------|-----|
| com.neovisionaries:nv-websocket-client      | CVE-2017-1000209 |
| FasterXML:jackson-dataformat-xml            | CVE-2016-3720 |
| org.jsoup:jsoup                             | CVE-2015-6748 |
| org.apache.groovy:groovy                    | CVE-2015-3253, CVE-2016-6814 |
| org.igniterealtime.smack:smack-core         | CVE-2016-10027 |
| com.thoughtworks.xstream:xstream            | CVE-2013-7285, CVE-2017-7957 |
| org.apache.commons:commons-compress         | CVE-2018-11771, CVE-2019-12402<br>CVE-2018-1324, CVE-2012-2098 |
| com.squareup.okhttp3:okhttp                 | CVE-2021-0341 |
| org.apache.httpcomponents:httpclient        | CVE-2015-5262, CVE-2014-3577 |
| com.itextpdf:itextpdf                       | CVE-2017-9096 |
| com.github.junrar:junrar                    | CVE-2018-12418 |
| com.google.guava:guava                      | CVE-2018-10237 |
| com.caverock:androidsvg                     | CVE-2017-1000498 |
| io.netty:netty                              | CVE-2018-12418, CVE-2014-0193<br>CVE-2016-4970, CVE-2014-3488 |
| com.squareup.retrofit2:retrofit             | CVE-2018-1000850 |
| org.zeroturnaround:zt-zip                   | CVE-2018-1002201 |
| ch.qos.logback:logback-core                 | CVE-2017-5929 |
| org.apache.jackrabbit:jackrabbit-webdav     | CVE-2015-1833, CVE-2016-6801 |
| org.conscrypt:conscrypt-android             | CVE-2017-13309 |
| org.apache.logging.log4j:log4j-core         | CVE-2021-44228, CVE-2021-45046<br>CVE-2017-5645 |
| org.apache.pdfbox:pdfbox                    | CVE-2016-2175, CVE-2018-8036<br>CVE-2018-11797, CVE-2019-0228 |
| com.fasterxml.jackson.core:jackson-databind | CVE-2019-17267, CVE-2020-8840<br>CVE-2021-20190, CVE-2019-14439<br>CVE-2018-11307, CVE-2019-14892<br>CVE-2020-36182, CVE-2018-19362<br>CVE-2018-19360, CVE-2019-14893<br>CVE-2017-17485, CVE-2018-5968<br>CVE-2019-12086, CVE-2018-12022<br>CVE-2018-19361, CVE-2020-9546<br>CVE-2019-12814 |
| org.bouncycastle:bcprov-jdkon             | CVE-2016-1000344, CVE-2016-1000341<br>CVE-2020-26939, CVE-2016-1000343<br>CVE-2018-1000613, CVE-2016-1000352<br>CVE-2016-1000345, CVE-2018-1000180<br>CVE-2020-28052, CVE-2016-1000346<br>CVE-2019-17359, CVE-2017-13098<br>CVE-2016-1000342, CVE-2015-6644<br>CVE-2016-1000339 |
| org.eclipse.jetty:jetty-server              | CVE-2011-4461, CVE-2016-4800<br>CVE-2018-12538, CVE-2019-17632<br>CVE-2019-10247, CVE-2019-10241 |
| org.eclipse.jetty:jetty-servlet             | CVE-2019-10246 |
| org.eclipse.jetty:jetty-security            | CVE-2017-9735 |
| org.eclipse.jetty:jetty-http                | CVE-2015-2080, CVE-2017-7656<br>CVE-2017-7657 |
| dom4j:dom4j                                 | CVE-2020-10683, CVE-2018-1000632 |
| io.netty:netty-all                          | CVE-2019-16869, CVE-2015-2156<br>CVE-2019-20444 |
| org.apache.openjpa:openjpa-lib              | CVE-2013-1768 |
| com.unboundid:unboundid-ldapsdk             | CVE-2018-1000134 |
| commons-beanutils:commons-beanutils         | CVE-2019-10086 |
| org.apache.cordova:framework                | CVE-2015-5256, CVE-2015-8320 |
| com.liulishuo.filedownloader:library        | CVE-2018-11248 |
| com.google.gson:gson                        | CVE-2022-25647 |
