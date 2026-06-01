package analyze;

import java.util.LinkedHashSet;
import java.util.Set;

public class Configuration {
    public boolean enableDebugLevel = false;
    private String targetAPKFile = "";
    private String androidPlatformJar = "";
    private String preBinary = "";
    private String postBinary = "";
    private String threadNumber = String.valueOf(Math.max(1, Runtime.getRuntime().availableProcessors()));
    private String patchFiles = "";
    private String targetClasses = "";
    private String cacheDir = resolveDefaultCacheDir();

    public Configuration() {
    }


    public String getPatchFiles() {
        return patchFiles;
    }

    public void setPatchFiles(String patchFiles) {
        this.patchFiles = patchFiles;
    }

    public String getTargetClasses() {
        return targetClasses;
    }

    public void setTargetClasses(String targetClasses) {
        this.targetClasses = targetClasses;
    }

    public Set<String> getTargetClassesSet() {
        Set<String> classes = new LinkedHashSet<>();
        if (targetClasses == null || targetClasses.trim().isEmpty()) {
            return classes;
        }
        String[] parts = targetClasses.split(",");
        for (String part : parts) {
            if (part == null) {
                continue;
            }
            String className = part.trim();
            if (className.endsWith(".*")) {
                className = className.substring(0, className.length() - 2);
            }
            if (className.endsWith(".")) {
                className = className.substring(0, className.length() - 1);
            }
            if (!className.isEmpty()) {
                classes.add(className);
            }
        }
        return classes;
    }

    public int getThreadNumber() {
        try {
            int parsed = Integer.parseInt(threadNumber);
            return Math.max(1, parsed);
        } catch (NumberFormatException ex) {
            return 1;
        }
    }

    public void setThreadNumber(String threadNumber) {
        this.threadNumber = threadNumber;
    }

    public String getCacheDir() {
        return cacheDir;
    }

    public void setCacheDir(String cacheDir) {
        this.cacheDir = cacheDir == null ? "" : cacheDir.trim();
    }

    public String getTargetAPKFile() {
        return targetAPKFile;
    }

    public void setTargetAPKFile(String targetAPKFile) {
        this.targetAPKFile = targetAPKFile;
    }

    public String getAndroidPlatformJar() {
        return androidPlatformJar;
    }

    public void setAndroidPlatformJar(String androidPlatformJar) {
        this.androidPlatformJar = androidPlatformJar;
    }

    public String getPreBinary() {
        return preBinary;
    }

    public void setPreBinary(String preBinary) {
        this.preBinary = preBinary;
    }

    public String getPostBinary() {
        return postBinary;
    }

    public void setPostBinary(String postBinary) {
        this.postBinary = postBinary;
    }

    public boolean isEnableDebugLevel() {
        return enableDebugLevel;
    }

    public void setEnableDebugLevel(boolean enableDebugLevel) {
        this.enableDebugLevel = enableDebugLevel;
    }

    private static String resolveDefaultCacheDir() {
        String env = System.getenv("PHUNTER_CACHE_DIR");
        if (env != null && !env.trim().isEmpty()) {
            return env.trim();
        }
        return "data/phunter_soot_cache";
    }
}
