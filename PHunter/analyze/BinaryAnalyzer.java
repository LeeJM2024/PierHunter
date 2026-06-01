package analyze;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.G;
import soot.Main;
import soot.PackManager;
import soot.Transform;
import soot.options.Options;

import java.io.File;
import java.io.IOException;
import java.util.Map;

public class BinaryAnalyzer extends Analyzer {
    private final boolean isPre;
    private final Configuration config;
    private final Logger logger = LoggerFactory.getLogger(getClass());

    public BinaryAnalyzer(Configuration config, boolean isPre) throws IOException {
        super(config);
        this.isPre = isPre;
        this.config = config;

        String inputPath = isPre ? config.getPreBinary() : config.getPostBinary();
        File inputFile = new File(inputPath);

        Map<String, ClassAttr> cachedClasses = PHunterCacheSupport.tryLoadAnalyzer(
                config,
                PHunterCacheSupport.DOMAIN_BINARY_ANALYSIS,
                inputFile,
                null,
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
                PHunterCacheSupport.DOMAIN_BINARY_ANALYSIS,
                inputFile,
                null,
                this.allClasses,
                logger
        );
    }

    private void initializeSoot() {
        G.reset();
        Options.v().set_whole_program(true);
        Options.v().set_src_prec(Options.src_prec_only_class);
        Options.v().set_output_format(Options.output_format_n);
        Options.v().set_allow_phantom_refs(true);
    }

    private SootCallGraph analyze() throws IOException {
        String inputPath;
        if (isPre) {
            inputPath = config.getPreBinary();
            logger.info("Analyzing the pre-patched binary {}", inputPath);
        } else {
            inputPath = config.getPostBinary();
            logger.info("Analyzing the post-patched binary {}", inputPath);
        }

        File inputFile = new File(inputPath);
        initializeSoot();

        SootCallGraph cg = new SootCallGraph(false);
        if (isPre) {
            PackManager.v().getPack("jtp").add(new Transform("jtp.pre", new CallGraphTransform(cg)));
        } else {
            PackManager.v().getPack("jtp").add(new Transform("jtp.post", new CallGraphTransform(cg)));
        }

        String[] sootArgs = new String[]{
                "-keep-line-number",
                "-process-dir",
                inputFile.getCanonicalPath(),
        };
        Main.main(sootArgs);

        cg.buildSootCallGraph();
        return cg;
    }

    public String getTPLName() {
        return isPre ? config.getPreBinary() : config.getPostBinary();
    }
}
