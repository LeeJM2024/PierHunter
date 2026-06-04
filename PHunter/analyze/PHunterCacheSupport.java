package analyze;

import org.slf4j.Logger;
import symbolicExec.MethodDigest;

import javax.script.ScriptEngineManager;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public final class PHunterCacheSupport {
    public static final String DOMAIN_BINARY_ANALYSIS = "binary_analysis";
    public static final String DOMAIN_APK_ANALYSIS = "apk_analysis";
    public static final String DOMAIN_PATCH_SUMMARY = "patch_summary";

    private static final String HASH_BUCKET_DIR = "soot_cache_hash";
    private static final String ALIAS_DIR = "_aliases";
    private static final String ALIAS_SUFFIX = ".latest";
    private static final String READY_FILE = ".ready";
    private static final String ANALYZER_PAYLOAD = "analyzer.bin";
    private static final String PATCH_SUMMARY_PAYLOAD = "patch_summary.bin";
    private static final String META_SOURCE = "source";
    private static final String META_SOURCE_HASH = "sourceHash";
    private static final String META_SCOPE_HASH = "scopeHash";
    private static final String META_SCOPE_SIZE = "scopeSize";
    private static final String META_CACHE_KEY = "cacheKey";

    private PHunterCacheSupport() {
    }

    public static Map<String, ClassAttr> tryLoadAnalyzer(
            Configuration config,
            String domain,
            File sourceFile,
            Set<String> scopeClasses,
            Logger logger
    ) {
        if (!isCacheEnabled(config) || sourceFile == null || !sourceFile.exists()) {
            return null;
        }
        try {
            List<String> normalizedScope = normalizeAnalyzerScope(domain, scopeClasses);
            String sourceHash = buildContentHash(sourceFile);
            String key = computeAnalyzerKey(sourceHash, normalizedScope);
            File entryDir = getEntryDir(config, domain, key);
            if (!isReady(entryDir, ANALYZER_PAYLOAD)) {
                if (!DOMAIN_BINARY_ANALYSIS.equals(domain)) {
                    return null;
                }
                String aliasKey = tryReadAliasKey(config, domain, sourceFile, normalizedScope, logger);
                if (aliasKey == null || aliasKey.isEmpty() || aliasKey.equals(key)) {
                    return null;
                }
                File aliasEntryDir = getEntryDir(config, domain, aliasKey);
                if (!isReady(aliasEntryDir, ANALYZER_PAYLOAD)) {
                    return null;
                }
                if (!isAliasEntryCompatible(aliasEntryDir, sourceHash, normalizedScope)) {
                    return null;
                }
                entryDir = aliasEntryDir;
                key = aliasKey;
            }
            Object loaded = readPayload(new File(entryDir, ANALYZER_PAYLOAD));
            if (!(loaded instanceof Map)) {
                return null;
            }
            if (DOMAIN_BINARY_ANALYSIS.equals(domain)) {
                try {
                    updateAlias(config, domain, sourceFile, normalizedScope, key, logger);
                } catch (Exception aliasEx) {
                    logger.warn("Failed to refresh cache alias for {}: {}", sourceFile.getAbsolutePath(), aliasEx.toString());
                }
            }
            logger.info("Cache hit [{}] key={}", domain, key);
            return (Map<String, ClassAttr>) loaded;
        } catch (Exception ex) {
            logger.warn("Failed to load cache [{}] for {}: {}", domain, sourceFile.getAbsolutePath(), ex.toString());
            return null;
        }
    }

    public static boolean storeAnalyzer(
            Configuration config,
            String domain,
            File sourceFile,
            Set<String> scopeClasses,
            Map<String, ClassAttr> allClasses,
            Logger logger
    ) {
        if (!isCacheEnabled(config) || sourceFile == null || !sourceFile.exists() || allClasses == null) {
            return false;
        }
        try {
            prepareAnalyzerForSerialization(allClasses, logger);
            List<String> normalizedScope = normalizeAnalyzerScope(domain, scopeClasses);
            String sourceHash = buildContentHash(sourceFile);
            String scopeHash = computeScopeHash(normalizedScope);
            String key = computeAnalyzerKey(sourceHash, normalizedScope);
            File entryDir = getEntryDir(config, domain, key);
            String metadata = buildAnalyzerMetadata(sourceFile, sourceHash, scopeHash, normalizedScope.size(), key);
            writePayload(entryDir, ANALYZER_PAYLOAD, allClasses, metadata);
            if (DOMAIN_BINARY_ANALYSIS.equals(domain)) {
                updateAlias(config, domain, sourceFile, normalizedScope, key, logger);
            }
            logger.info("Cache stored [{}] key={}", domain, key);
            return true;
        } catch (Exception ex) {
            logger.warn("Failed to store cache [{}] for {}", domain, sourceFile.getAbsolutePath(), ex);
            return false;
        }
    }

    public static PatchSummary.PatchSummarySnapshot tryLoadPatchSummary(
            Configuration config,
            String preBinary,
            String postBinary,
            String patchFiles,
            Logger logger
    ) {
        if (!isCacheEnabled(config)) {
            return null;
        }
        try {
            String key = computePatchSummaryKey(preBinary, postBinary, patchFiles);
            File entryDir = getEntryDir(config, DOMAIN_PATCH_SUMMARY, key);
            if (!isReady(entryDir, PATCH_SUMMARY_PAYLOAD)) {
                return null;
            }
            Object loaded = readPayload(new File(entryDir, PATCH_SUMMARY_PAYLOAD));
            if (!(loaded instanceof PatchSummary.PatchSummarySnapshot)) {
                return null;
            }
            logger.info("Cache hit [{}] key={}", DOMAIN_PATCH_SUMMARY, key);
            return (PatchSummary.PatchSummarySnapshot) loaded;
        } catch (Exception ex) {
            logger.warn("Failed to load cache [{}]: {}", DOMAIN_PATCH_SUMMARY, ex.toString());
            return null;
        }
    }

    public static void storePatchSummary(
            Configuration config,
            String preBinary,
            String postBinary,
            String patchFiles,
            PatchSummary.PatchSummarySnapshot snapshot,
            Logger logger
    ) {
        if (!isCacheEnabled(config) || snapshot == null) {
            return;
        }
        try {
            String key = computePatchSummaryKey(preBinary, postBinary, patchFiles);
            File entryDir = getEntryDir(config, DOMAIN_PATCH_SUMMARY, key);
            writePayload(entryDir, PATCH_SUMMARY_PAYLOAD, snapshot, "patchFiles=" + patchFiles + "\n");
            logger.info("Cache stored [{}] key={}", DOMAIN_PATCH_SUMMARY, key);
        } catch (Exception ex) {
            logger.warn("Failed to store cache [{}]: {}", DOMAIN_PATCH_SUMMARY, ex.toString());
        }
    }

    private static boolean isCacheEnabled(Configuration config) {
        if (config == null) {
            return false;
        }
        String cacheDir = config.getCacheDir();
        return cacheDir != null && !cacheDir.trim().isEmpty();
    }

    private static File getEntryDir(Configuration config, String domain, String key) {
        File root = new File(config.getCacheDir());
        File domainDir = new File(root, domain);
        File bucket = new File(domainDir, HASH_BUCKET_DIR);
        return new File(bucket, key);
    }

    private static boolean isReady(File entryDir, String payloadName) {
        if (entryDir == null) {
            return false;
        }
        File ready = new File(entryDir, READY_FILE);
        File payload = new File(entryDir, payloadName);
        return ready.exists() && payload.exists();
    }

    private static void writePayload(File entryDir, String payloadName, Object payload, String metadata) throws IOException {
        if (!entryDir.exists() && !entryDir.mkdirs()) {
            throw new IOException("Failed to create cache entry directory: " + entryDir.getAbsolutePath());
        }
        File payloadFile = new File(entryDir, payloadName);
        try (ObjectOutputStream oos = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream(payloadFile)))) {
            oos.writeObject(payload);
        }
        File readyFile = new File(entryDir, READY_FILE);
        Files.write(readyFile.toPath(), (metadata == null ? "" : metadata).getBytes(StandardCharsets.UTF_8));
    }

    private static Object readPayload(File payloadFile) throws IOException, ClassNotFoundException {
        try (ObjectInputStream ois = new ObjectInputStream(new BufferedInputStream(new FileInputStream(payloadFile)))) {
            return ois.readObject();
        }
    }

    private static String computeAnalyzerKey(String sourceHash, List<String> normalizedScope) {
        if (normalizedScope.isEmpty()) {
            return sourceHash;
        }
        String scopeJoined = String.join("\n", normalizedScope);
        return sha256Text("src=" + sourceHash + "\nscope=" + scopeJoined);
    }

    private static String computePatchSummaryKey(String preBinary, String postBinary, String patchFiles) throws IOException {
        File preFile = new File(preBinary);
        File postFile = new File(postBinary);
        if (!preFile.exists() || !postFile.exists()) {
            throw new IOException("Template binaries not found when computing patch summary cache key.");
        }
        String preHash = buildContentHash(preFile);
        String postHash = buildContentHash(postFile);

        List<String> patchHashes = new ArrayList<>();
        List<File> patchFileList = parsePatchFiles(patchFiles);
        for (File patchFile : patchFileList) {
            if (!patchFile.exists()) {
                patchHashes.add("missing:" + patchFile.getAbsolutePath());
                continue;
            }
            patchHashes.add(buildContentHash(patchFile));
        }

        String patchJoined = String.join("\n", patchHashes);
        return sha256Text("pre=" + preHash + "\npost=" + postHash + "\npatch=" + patchJoined);
    }

    private static List<File> parsePatchFiles(String patchFiles) {
        List<File> files = new ArrayList<>();
        if (patchFiles == null || patchFiles.trim().isEmpty()) {
            return files;
        }
        String[] parts = patchFiles.split(";");
        for (String part : parts) {
            if (part == null) {
                continue;
            }
            String trimmed = part.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            files.add(new File(trimmed));
        }
        return files;
    }

    private static List<String> normalizeScope(Set<String> scopeClasses) {
        Set<String> normalized = new LinkedHashSet<>();
        if (scopeClasses == null) {
            return new ArrayList<>();
        }
        for (String scope : scopeClasses) {
            if (scope == null) {
                continue;
            }
            String value = scope.trim();
            if (value.isEmpty()) {
                continue;
            }
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
        List<String> sorted = new ArrayList<>(normalized);
        sorted.sort(String::compareTo);
        return sorted;
    }

    private static List<String> normalizeAnalyzerScope(String domain, Set<String> scopeClasses) {
        if (DOMAIN_APK_ANALYSIS.equals(domain)) {
            return new ArrayList<>();
        }
        return normalizeScope(scopeClasses);
    }

    private static String computeScopeHash(List<String> normalizedScope) {
        if (normalizedScope == null || normalizedScope.isEmpty()) {
            return "";
        }
        return sha256Text(String.join("\n", normalizedScope));
    }

    private static String buildAnalyzerMetadata(
            File sourceFile,
            String sourceHash,
            String scopeHash,
            int scopeSize,
            String cacheKey
    ) throws IOException {
        StringBuilder sb = new StringBuilder(256);
        sb.append(META_SOURCE).append('=').append(sourceFile.getCanonicalPath()).append('\n');
        sb.append(META_SOURCE_HASH).append('=').append(sourceHash).append('\n');
        sb.append(META_SCOPE_HASH).append('=').append(scopeHash).append('\n');
        sb.append(META_SCOPE_SIZE).append('=').append(scopeSize).append('\n');
        sb.append(META_CACHE_KEY).append('=').append(cacheKey).append('\n');
        return sb.toString();
    }

    private static File getAliasDir(Configuration config, String domain) {
        File root = new File(config.getCacheDir());
        File domainDir = new File(root, domain);
        return new File(domainDir, ALIAS_DIR);
    }

    private static String buildAliasName(File sourceFile, List<String> normalizedScope) {
        String baseName = sourceFile.getName();
        if (baseName == null || baseName.trim().isEmpty()) {
            return null;
        }
        if (normalizedScope == null || normalizedScope.isEmpty()) {
            return baseName;
        }
        String scopeHash = computeScopeHash(normalizedScope);
        return baseName + "." + scopeHash.substring(0, Math.min(16, scopeHash.length()));
    }

    private static void updateAlias(
            Configuration config,
            String domain,
            File sourceFile,
            List<String> normalizedScope,
            String key,
            Logger logger
    ) throws IOException {
        String aliasName = buildAliasName(sourceFile, normalizedScope);
        if (aliasName == null || aliasName.isEmpty()) {
            return;
        }
        File aliasDir = getAliasDir(config, domain);
        if (!aliasDir.exists() && !aliasDir.mkdirs()) {
            throw new IOException("Failed to create alias directory: " + aliasDir.getAbsolutePath());
        }
        File aliasFile = new File(aliasDir, aliasName + ALIAS_SUFFIX);
        Path tempFile = Files.createTempFile(aliasDir.toPath(), "alias_", ".tmp");
        Files.write(tempFile, (key + "\n").getBytes(StandardCharsets.UTF_8));
        try {
            Files.move(tempFile, aliasFile.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException moveEx) {
            Files.move(tempFile, aliasFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
        }
        logger.info("Cache alias updated [{}] {} -> {}", domain, aliasFile.getName(), key);
    }

    private static String tryReadAliasKey(
            Configuration config,
            String domain,
            File sourceFile,
            List<String> normalizedScope,
            Logger logger
    ) {
        try {
            String aliasName = buildAliasName(sourceFile, normalizedScope);
            if (aliasName == null || aliasName.isEmpty()) {
                return null;
            }
            File aliasFile = new File(getAliasDir(config, domain), aliasName + ALIAS_SUFFIX);
            if (!aliasFile.exists() || !aliasFile.isFile()) {
                return null;
            }
            String key = Files.readString(aliasFile.toPath(), StandardCharsets.UTF_8).trim();
            if (key.isEmpty()) {
                return null;
            }
            return key;
        } catch (Exception ex) {
            logger.warn("Failed to read cache alias for {}: {}", sourceFile.getAbsolutePath(), ex.toString());
            return null;
        }
    }

    private static boolean isAliasEntryCompatible(
            File entryDir,
            String sourceHash,
            List<String> normalizedScope
    ) {
        try {
            Map<String, String> metadata = readMetadata(entryDir);
            String metaSourceHash = metadata.get(META_SOURCE_HASH);
            if (metaSourceHash == null || metaSourceHash.trim().isEmpty()) {
                return false;
            }
            if (!sourceHash.equals(metaSourceHash.trim())) {
                return false;
            }
            String expectedScopeHash = computeScopeHash(normalizedScope);
            String metaScopeHash = metadata.get(META_SCOPE_HASH);
            if (metaScopeHash == null || metaScopeHash.trim().isEmpty()) {
                return expectedScopeHash.isEmpty();
            }
            return expectedScopeHash.equals(metaScopeHash.trim());
        } catch (Exception ignored) {
            return false;
        }
    }

    private static Map<String, String> readMetadata(File entryDir) throws IOException {
        Map<String, String> metadata = new LinkedHashMap<>();
        File readyFile = new File(entryDir, READY_FILE);
        if (!readyFile.exists() || !readyFile.isFile()) {
            return metadata;
        }
        List<String> lines = Files.readAllLines(readyFile.toPath(), StandardCharsets.UTF_8);
        for (String line : lines) {
            if (line == null) {
                continue;
            }
            int idx = line.indexOf('=');
            if (idx <= 0 || idx == line.length() - 1) {
                continue;
            }
            String key = line.substring(0, idx).trim();
            String value = line.substring(idx + 1).trim();
            if (!key.isEmpty()) {
                metadata.put(key, value);
            }
        }
        return metadata;
    }

    private static String buildContentHash(File sourceFile) throws IOException {
        MessageDigest md = sha256Digest();
        try (FileInputStream in = new FileInputStream(sourceFile)) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) > 0) {
                md.update(buffer, 0, read);
            }
        }
        return toHex(md.digest());
    }

    private static String sha256Text(String raw) {
        MessageDigest digest = sha256Digest();
        byte[] bytes = raw == null ? new byte[0] : raw.getBytes(StandardCharsets.UTF_8);
        digest.update(bytes);
        return toHex(digest.digest());
    }

    private static MessageDigest sha256Digest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format(Locale.ROOT, "%02x", b));
        }
        return sb.toString();
    }

    private static void prepareAnalyzerForSerialization(Map<String, ClassAttr> allClasses, Logger logger) {
        ensureDigestScriptEngines();
        Set<MethodAttr> visitedMethods = new LinkedHashSet<>();
        int skippedDigests = 0;
        for (ClassAttr clazz : allClasses.values()) {
            if (clazz == null || clazz.methods == null) {
                continue;
            }
            for (MethodAttr method : clazz.methods) {
                if (method == null || !visitedMethods.add(method)) {
                    continue;
                }
                try {
                    if (method.hasBody && method.digest == null && method.body != null) {
                        method.digest = new MethodDigest(method.body, null);
                    }
                    if (method.digest != null) {
                        method.digest.prepareForSerialization();
                    }
                } catch (RuntimeException ex) {
                    method.digest = null;
                    skippedDigests += 1;
                    if (skippedDigests <= 20) {
                        String signature = method.signature == null ? "<unknown>" : method.signature;
                        logger.warn("Skip unserializable method digest while preparing APK cache: {} ({})", signature, ex.toString());
                    }
                }
            }
        }
        if (skippedDigests > 0) {
            logger.warn("Skipped {} method digest(s) while preparing analyzer cache; structural class/method cache will still be stored.", skippedDigests);
        }
    }

    private static void ensureDigestScriptEngines() {
        if (PatchPresentTest_new.sePy != null && PatchPresentTest_new.seJs != null) {
            return;
        }
        ScriptEngineManager manager = new ScriptEngineManager();
        if (PatchPresentTest_new.sePy == null) {
            PatchPresentTest_new.sePy = manager.getEngineByName("python");
        }
        if (PatchPresentTest_new.seJs == null) {
            PatchPresentTest_new.seJs = manager.getEngineByName("JavaScript");
        }
    }
}
