package analyze;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.Main;
import soot.PackManager;
import soot.Transform;
import soot.options.Options;

import java.io.File;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

public class APKAnalyzer extends Analyzer {
    private final Configuration config;
    private final Logger logger = LoggerFactory.getLogger(getClass());
    private boolean fullApkCacheReady = false;

    public APKAnalyzer(Configuration config) throws IOException {
        super(config);
        this.config = config;

        File inputFile = new File(config.getTargetAPKFile());
        Set<String> targetScope = config.getTargetClassesSet();

        Map<String, ClassAttr> cachedClasses = PHunterCacheSupport.tryLoadAnalyzer(
                config,
                PHunterCacheSupport.DOMAIN_APK_ANALYSIS,
                inputFile,
                null,
                logger
        );
        if (cachedClasses != null) {
            this.allClasses = selectClassesForScope(cachedClasses, targetScope);
            rebuildAllMethodsFromClasses();
            this.fullApkCacheReady = true;
            return;
        }

        SootCallGraph cg = analyze();
        buildCG(cg);
        if (targetScope.isEmpty()) {
            this.fullApkCacheReady = PHunterCacheSupport.storeAnalyzer(
                    config,
                    PHunterCacheSupport.DOMAIN_APK_ANALYSIS,
                    inputFile,
                    null,
                    this.allClasses,
                    logger
            );
        } else {
            logger.info("Skip storing scoped APK analysis; build the full APK cache with --prewarmAPKOnly first.");
        }
    }

    public boolean isFullApkCacheReady() {
        return fullApkCacheReady;
    }

    private void initializeSoot() {
        soot.G.reset();
        Options.v().set_allow_phantom_refs(true);
        Options.v().set_whole_program(true);
        Options.v().set_no_bodies_for_excluded(true);

        Options.v().set_force_android_jar(config.getAndroidPlatformJar());
        Options.v().set_src_prec(Options.src_prec_apk);
        // Soot 4.7.x removed set_process_multiple_dex; keep dex discovery enabled.
        Options.v().set_search_dex_in_archives(true);
        Options.v().set_keep_line_number(false);
        Options.v().set_keep_offset(false);
        Options.v().set_throw_analysis(Options.throw_analysis_dalvik);
        Options.v().set_ignore_resolution_errors(true);
        Options.v().set_output_format(Options.output_format_n);
    }

    private SootCallGraph analyze() throws IOException {
        initializeSoot();

        SootCallGraph cg = new SootCallGraph(true, config.getTargetClassesSet());
        File inputFile = new File(config.getTargetAPKFile());
        PackManager.v().getPack("jtp").add(new Transform("jtp.apk", new CallGraphTransform(cg)));
        logger.info("Analyzing the apk {}", config.getTargetAPKFile());

        String[] sootArgs = new String[]{
                "-process-dir",
                inputFile.getCanonicalPath(),
        };
        CallGraphTransform.beginApkProgress(inputFile.getName());
        try {
            Main.main(sootArgs);
        } finally {
            CallGraphTransform.finishApkProgress();
        }
        cg.buildSootCallGraph();
        return cg;
    }

    private Map<String, ClassAttr> selectClassesForScope(Map<String, ClassAttr> classes, Set<String> rawScope) {
        Set<String> scope = normalizeScope(rawScope);
        if (scope.isEmpty()) {
            return classes;
        }
        Set<String> prefixes = buildScopePrefixes(scope);
        Map<String, ClassAttr> selected = new LinkedHashMap<>();
        for (Map.Entry<String, ClassAttr> entry : classes.entrySet()) {
            ClassAttr attr = entry.getValue();
            String className = attr != null && attr.name != null ? attr.name : entry.getKey();
            if (scope.contains(className) || startsWithAny(className, prefixes)) {
                selected.put(entry.getKey(), attr);
            }
        }
        logger.info(
                "Loaded full APK cache and selected {} / {} classes for current limitClasses scope",
                selected.size(),
                classes.size()
        );
        return selected;
    }

    private Set<String> normalizeScope(Set<String> rawScope) {
        Set<String> normalized = new LinkedHashSet<>();
        if (rawScope == null) {
            return normalized;
        }
        for (String scope : rawScope) {
            if (scope == null) {
                continue;
            }
            String value = scope.trim();
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

    private Set<String> buildScopePrefixes(Set<String> scope) {
        Set<String> prefixes = new LinkedHashSet<>();
        for (String target : scope) {
            prefixes.add(target + ".");
            int lastDot = target.lastIndexOf('.');
            if (lastDot > 0) {
                prefixes.add(target.substring(0, lastDot + 1));
            }
        }
        return prefixes;
    }

    private boolean startsWithAny(String className, Set<String> prefixes) {
        if (className == null) {
            return false;
        }
        for (String prefix : prefixes) {
            if (className.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    public String getAPKName() {
        return config.getTargetAPKFile();
    }
}
