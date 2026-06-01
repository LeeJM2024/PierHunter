package analyze;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.Main;
import soot.PackManager;
import soot.Transform;
import soot.options.Options;

import java.io.File;
import java.io.IOException;
import java.util.Map;
import java.util.Set;

public class APKAnalyzer extends Analyzer {
    private final Configuration config;
    private final Logger logger = LoggerFactory.getLogger(getClass());

    public APKAnalyzer(Configuration config) throws IOException {
        super(config);
        this.config = config;

        File inputFile = new File(config.getTargetAPKFile());
        Set<String> targetScope = config.getTargetClassesSet();

        Map<String, ClassAttr> cachedClasses = PHunterCacheSupport.tryLoadAnalyzer(
                config,
                PHunterCacheSupport.DOMAIN_APK_ANALYSIS,
                inputFile,
                targetScope,
                logger
        );
        if (cachedClasses != null) {
            this.allClasses = cachedClasses;
            rebuildAllMethodsFromClasses();
            return;
        }

        SootCallGraph cg = analyze();
        buildCG(cg);
        PHunterCacheSupport.storeAnalyzer(
                config,
                PHunterCacheSupport.DOMAIN_APK_ANALYSIS,
                inputFile,
                targetScope,
                this.allClasses,
                logger
        );
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

    public String getAPKName() {
        return config.getTargetAPKFile();
    }
}
