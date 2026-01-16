/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package reva.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;

/**
 * Computes and indexes function fingerprints for cross-program matching.
 *
 * <p>Goal: match "the same" function across multiple executables where addresses differ,
 * but code is identical or near-identical. The fingerprint is intentionally independent
 * of address and symbol names.</p>
 *
 * <p>Implementation details:
 * - Uses a normalized signature of the first N instructions (mnemonics + operand-type categories)
 * - Includes coarse size metadata (function body address count and sampled instruction count)
 * - Hashes the normalized signature via SHA-256</p>
 */
public final class FunctionFingerprintUtil {
    /** Default number of instructions to sample from each function for fingerprinting. */
    public static final int DEFAULT_MAX_INSTRUCTIONS = 64;

    private static final int MAX_CANDIDATES_RETURNED = 25;

    private static final Map<String, CachedProgramIndex> INDEX_CACHE = new ConcurrentHashMap<>();

    private FunctionFingerprintUtil() {
        // utility
    }

    /**
     * A minimal descriptor for a function match candidate.
     *
     * @param programPath Ghidra project pathname (e.g., "/swkotor.exe")
     * @param functionName Function name in that program
     * @param entryPoint Function entry point
     */
    /**
     * A function match candidate with similarity score.
     */
    public record Candidate(String programPath, String functionName, Address entryPoint) {
        /**
         * Create a candidate with similarity score.
         */
        public record Scored(Candidate candidate, double similarityScore) {}
    }

    private record CachedProgramIndex(long programModificationNumber, int maxInstructions,
                                      Map<String, List<Candidate>> byFingerprint) {}

    /**
     * Cached signature index for fast fuzzy matching.
     * Stores canonical signatures and function metadata for efficient similarity search.
     */
    private record CachedSignatureIndex(long programModificationNumber, int maxInstructions,
                                        List<IndexedFunction> functions) {
        record IndexedFunction(Candidate candidate, String signature, long bodySize, int instructionCount) {}
    }

    private static final Map<String, CachedSignatureIndex> SIGNATURE_INDEX_CACHE = new ConcurrentHashMap<>();

    /**
     * Compute a SHA-256 fingerprint for a function.
     *
     * @param program Program containing the function
     * @param function Function to fingerprint
     * @return fingerprint string (hex), or null if fingerprinting fails
     */
    public static String computeFingerprint(Program program, Function function) {
        return computeFingerprint(program, function, DEFAULT_MAX_INSTRUCTIONS);
    }

    /**
     * Compute a SHA-256 fingerprint for a function using the first {@code maxInstructions}.
     *
     * @param program Program containing the function
     * @param function Function to fingerprint
     * @param maxInstructions Number of instructions to include (recommended: 32-128)
     * @return fingerprint string (hex), or null if fingerprinting fails
     */
    public static String computeFingerprint(Program program, Function function, int maxInstructions) {
        try {
            String canonical = buildCanonicalSignature(program, function, maxInstructions);
            if (canonical == null || canonical.isEmpty()) {
                return null;
            }
            return sha256Hex(canonical);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Find fingerprint matches for {@code fingerprint} in {@code targetProgram}.
     *
     * @param targetProgram Target program to search
     * @param fingerprint Fingerprint string
     * @param maxInstructions Fingerprint configuration used for the index
     * @return candidate list (possibly empty)
     */
    public static List<Candidate> findMatches(Program targetProgram, String fingerprint, int maxInstructions) {
        if (fingerprint == null || fingerprint.isEmpty() || targetProgram == null) {
            return List.of();
        }
        CachedProgramIndex index = getOrBuildIndex(targetProgram, maxInstructions);
        List<Candidate> matches = index.byFingerprint().get(fingerprint);
        if (matches == null || matches.isEmpty()) {
            return List.of();
        }
        if (matches.size() <= MAX_CANDIDATES_RETURNED) {
            return matches;
        }
        return matches.subList(0, MAX_CANDIDATES_RETURNED);
    }

    /**
     * Get (or build) a fingerprint index for a program.
     *
     * @param program Program to index
     * @param maxInstructions Instruction sampling size
     * @return cached index
     */
    public static CachedProgramIndex getOrBuildIndex(Program program, int maxInstructions) {
        String programPath = program.getDomainFile().getPathname();
        long mod = program.getModificationNumber();

        CachedProgramIndex cached = INDEX_CACHE.get(programPath);
        if (cached != null && cached.programModificationNumber == mod && cached.maxInstructions == maxInstructions) {
            return cached;
        }

        Map<String, List<Candidate>> byFingerprint = new HashMap<>();
        FunctionIterator it = program.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            if (f == null || f.isExternal()) {
                continue;
            }
            String fp = computeFingerprint(program, f, maxInstructions);
            if (fp == null) {
                continue;
            }
            Candidate cand = new Candidate(programPath, f.getName(), f.getEntryPoint());
            byFingerprint.computeIfAbsent(fp, k -> new ArrayList<>()).add(cand);
        }

        // Make candidate lists deterministic
        for (Map.Entry<String, List<Candidate>> e : byFingerprint.entrySet()) {
            e.getValue().sort((a, b) -> a.entryPoint().compareTo(b.entryPoint()));
        }

        CachedProgramIndex built = new CachedProgramIndex(mod, maxInstructions,
            Collections.unmodifiableMap(byFingerprint));
        INDEX_CACHE.put(programPath, built);
        return built;
    }

    private static String buildCanonicalSignature(Program program, Function function, int maxInstructions) {
        Listing listing = program.getListing();
        InstructionIterator instrIter = listing.getInstructions(function.getBody(), true);

        StringBuilder sb = new StringBuilder(4096);

        long bodySize = 0;
        try {
            bodySize = function.getBody().getNumAddresses();
        } catch (Exception e) {
            bodySize = 0;
        }

        // Add coarse metadata (helps reduce collisions for tiny stubs)
        sb.append("B=").append(bodySize).append(';');
        sb.append("N=").append(maxInstructions).append(';');

        int count = 0;
        while (instrIter.hasNext() && count < maxInstructions) {
            Instruction instr = instrIter.next();
            if (instr == null) {
                continue;
            }
            sb.append(instr.getMnemonicString());
            sb.append('(');
            int opCount = instr.getNumOperands();
            for (int i = 0; i < opCount; i++) {
                int opType = instr.getOperandType(i);
                sb.append(operandTypeCategory(opType));
                if (i + 1 < opCount) {
                    sb.append(',');
                }
            }
            sb.append(')');
            sb.append(';');
            count++;
        }

        sb.append("C=").append(count).append(';');
        return sb.toString();
    }

    /**
     * Map Ghidra operand type bitmask to a small canonical category string.
     * This intentionally discards concrete values (addresses/immediates) to survive rebases.
     */
    private static String operandTypeCategory(int operandType) {
        // Order matters: some operands have multiple bits.
        if ((operandType & OperandType.REGISTER) != 0) {
            return "reg";
        }
        if ((operandType & OperandType.SCALAR) != 0) {
            return "imm";
        }
        if ((operandType & OperandType.ADDRESS) != 0) {
            return "addr";
        }
        if ((operandType & OperandType.DYNAMIC) != 0) {
            return "dyn";
        }
        if ((operandType & OperandType.DATA) != 0) {
            return "data";
        }
        if ((operandType & OperandType.IMMEDIATE) != 0) {
            return "imm";
        }
        // NOTE: OperandType.MEMORY was removed in Ghidra 12.0
        // Memory operands are typically covered by ADDRESS or DATA types
        return "other";
    }

    /**
     * Compute the canonical signature (without hashing) for similarity matching.
     * This is the same format used for exact fingerprints but returned as a string.
     *
     * @param program Program containing the function
     * @param function Function to analyze
     * @param maxInstructions Number of instructions to include
     * @return canonical signature string, or null if computation fails
     */
    public static String computeCanonicalSignature(Program program, Function function, int maxInstructions) {
        try {
            return buildCanonicalSignature(program, function, maxInstructions);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Find fuzzy matches for a source function in a target program using similarity scoring.
     * Returns candidates sorted by similarity (highest first).
     * 
     * <p>Optimized for large-scale matching (16k+ functions) by:
     * - Pre-indexing target program signatures (cached)
     * - Size-based pre-filtering to reduce comparisons
     * - Early termination for perfect matches
     * - Limiting expensive Levenshtein calculations
     *
     * @param sourceProgram Source program containing the reference function
     * @param sourceFunction Source function to match
     * @param targetProgram Target program to search
     * @param maxInstructions Number of instructions to use for comparison
     * @param minSimilarity Minimum similarity score (0.0-1.0) to include in results
     * @param maxResults Maximum number of results to return
     * @return List of scored candidates, sorted by similarity (highest first)
     */
    public static List<Candidate.Scored> findFuzzyMatches(Program sourceProgram, Function sourceFunction,
            Program targetProgram, int maxInstructions, double minSimilarity, int maxResults) {
        if (sourceFunction == null || targetProgram == null) {
            return List.of();
        }

        String sourceSig = computeCanonicalSignature(sourceProgram, sourceFunction, maxInstructions);
        if (sourceSig == null || sourceSig.isEmpty()) {
            return List.of();
        }

        // Extract source function metadata for size filtering
        long sourceBodySize = 0;
        int sourceInstructionCount = 0;
        try {
            sourceBodySize = sourceFunction.getBody().getNumAddresses();
            // Extract instruction count from signature (format: "C=64;")
            int cIdx = sourceSig.indexOf("C=");
            if (cIdx >= 0) {
                int endIdx = sourceSig.indexOf(';', cIdx);
                if (endIdx > cIdx) {
                    try {
                        sourceInstructionCount = Integer.parseInt(sourceSig.substring(cIdx + 2, endIdx));
                    } catch (NumberFormatException e) {
                        // Ignore
                    }
                }
            }
        } catch (Exception e) {
            // Ignore size extraction errors
        }

        // Get or build signature index for target program
        CachedSignatureIndex index = getOrBuildSignatureIndex(targetProgram, maxInstructions);

        List<Candidate.Scored> scored = new ArrayList<>();
        Candidate.Scored perfectMatch = null;

        // Size-based pre-filtering: only compare functions with similar sizes
        // This dramatically reduces comparisons for large programs
        double sizeTolerance = 0.5; // Allow 50% size difference
        long minSize = (long) (sourceBodySize * (1.0 - sizeTolerance));
        long maxSize = (long) (sourceBodySize * (1.0 + sizeTolerance));
        int minInstrCount = Math.max(1, (int) (sourceInstructionCount * (1.0 - sizeTolerance)));
        int maxInstrCount = (int) (sourceInstructionCount * (1.0 + sizeTolerance)) + 1;

        for (CachedSignatureIndex.IndexedFunction indexedFunc : index.functions()) {
            // Quick size-based pre-filter (avoids expensive signature computation)
            if (sourceBodySize > 0 && indexedFunc.bodySize() > 0) {
                if (indexedFunc.bodySize() < minSize || indexedFunc.bodySize() > maxSize) {
                    continue;
                }
            }
            if (sourceInstructionCount > 0 && indexedFunc.instructionCount() > 0) {
                if (indexedFunc.instructionCount() < minInstrCount || 
                    indexedFunc.instructionCount() > maxInstrCount) {
                    continue;
                }
            }

            String targetSig = indexedFunc.signature();
            if (targetSig == null || targetSig.isEmpty()) {
                continue;
            }

            // Fast path: exact match (no need for Levenshtein)
            if (sourceSig.equals(targetSig)) {
                perfectMatch = new Candidate.Scored(indexedFunc.candidate(), 1.0);
                break; // Early termination for perfect match
            }

            // Quick length-based filter before expensive Levenshtein
            int lenDiff = Math.abs(sourceSig.length() - targetSig.length());
            int maxLen = Math.max(sourceSig.length(), targetSig.length());
            if (maxLen > 0) {
                double lengthSimilarity = 1.0 - ((double) lenDiff / maxLen);
                // If length similarity is too low, skip expensive Levenshtein
                if (lengthSimilarity < minSimilarity * 0.7) {
                    continue;
                }
            }

            double similarity = computeSignatureSimilarity(sourceSig, targetSig);
            if (similarity >= minSimilarity) {
                scored.add(new Candidate.Scored(indexedFunc.candidate(), similarity));
            }
        }

        // If we found a perfect match, return it immediately
        if (perfectMatch != null) {
            return List.of(perfectMatch);
        }

        // Sort by similarity (highest first), then by address for determinism
        scored.sort((a, b) -> {
            int cmp = Double.compare(b.similarityScore(), a.similarityScore());
            if (cmp != 0) {
                return cmp;
            }
            return a.candidate().entryPoint().compareTo(b.candidate().entryPoint());
        });

        if (scored.size() <= maxResults) {
            return scored;
        }
        return scored.subList(0, maxResults);
    }

    /**
     * Get or build a signature index for a program (cached for performance).
     * This pre-computes all function signatures to avoid recomputation during fuzzy matching.
     *
     * @param program Program to index
     * @param maxInstructions Instruction sampling size
     * @return cached signature index
     */
    private static CachedSignatureIndex getOrBuildSignatureIndex(Program program, int maxInstructions) {
        String programPath = program.getDomainFile().getPathname();
        long mod = program.getModificationNumber();

        CachedSignatureIndex cached = SIGNATURE_INDEX_CACHE.get(programPath);
        if (cached != null && cached.programModificationNumber == mod && 
            cached.maxInstructions == maxInstructions) {
            return cached;
        }

        List<CachedSignatureIndex.IndexedFunction> indexed = new ArrayList<>();
        FunctionIterator it = program.getFunctionManager().getFunctions(true);
        String targetPath = program.getDomainFile().getPathname();

        while (it.hasNext()) {
            Function f = it.next();
            if (f == null || f.isExternal()) {
                continue;
            }

            String sig = computeCanonicalSignature(program, f, maxInstructions);
            if (sig == null || sig.isEmpty()) {
                continue;
            }

            long bodySize = 0;
            int instructionCount = 0;
            try {
                bodySize = f.getBody().getNumAddresses();
                // Extract instruction count from signature
                int cIdx = sig.indexOf("C=");
                if (cIdx >= 0) {
                    int endIdx = sig.indexOf(';', cIdx);
                    if (endIdx > cIdx) {
                        try {
                            instructionCount = Integer.parseInt(sig.substring(cIdx + 2, endIdx));
                        } catch (NumberFormatException e) {
                            // Ignore
                        }
                    }
                }
            } catch (Exception e) {
                // Ignore size extraction errors
            }

            Candidate cand = new Candidate(targetPath, f.getName(), f.getEntryPoint());
            indexed.add(new CachedSignatureIndex.IndexedFunction(cand, sig, bodySize, instructionCount));
        }

        // Sort by address for determinism
        indexed.sort((a, b) -> a.candidate().entryPoint().compareTo(b.candidate().entryPoint()));

        CachedSignatureIndex built = new CachedSignatureIndex(mod, maxInstructions,
            Collections.unmodifiableList(indexed));
        SIGNATURE_INDEX_CACHE.put(programPath, built);
        return built;
    }

    /**
     * Compute similarity between two canonical signatures using normalized edit distance.
     * Returns a score between 0.0 (completely different) and 1.0 (identical).
     *
     * @param sig1 First canonical signature
     * @param sig2 Second canonical signature
     * @return similarity score (0.0-1.0)
     */
    public static double computeSignatureSimilarity(String sig1, String sig2) {
        if (sig1 == null || sig2 == null || sig1.isEmpty() || sig2.isEmpty()) {
            return 0.0;
        }
        if (sig1.equals(sig2)) {
            return 1.0;
        }

        // Use normalized Levenshtein distance
        int maxLen = Math.max(sig1.length(), sig2.length());
        if (maxLen == 0) {
            return 1.0;
        }

        int distance = levenshteinDistance(sig1, sig2);
        return 1.0 - ((double) distance / maxLen);
    }

    /**
     * Compute Levenshtein (edit) distance between two strings.
     * Optimized with early termination for large differences.
     */
    private static int levenshteinDistance(String s1, String s2) {
        int m = s1.length();
        int n = s2.length();
        
        // Early termination: if length difference is too large, skip expensive calculation
        int lenDiff = Math.abs(m - n);
        int maxLen = Math.max(m, n);
        if (maxLen > 0 && lenDiff > maxLen * 0.5) {
            // Return approximate distance for very different lengths
            return lenDiff + Math.min(m, n);
        }
        
        // Use space-optimized version for large strings (O(min(m,n)) space instead of O(m*n))
        if (m < n) {
            // Swap to ensure m >= n for space optimization
            String temp = s1;
            s1 = s2;
            s2 = temp;
            int tempLen = m;
            m = n;
            n = tempLen;
        }
        
        // Space-optimized: only keep two rows
        int[] prev = new int[n + 1];
        int[] curr = new int[n + 1];
        
        // Initialize first row
        for (int j = 0; j <= n; j++) {
            prev[j] = j;
        }
        
        // Compute distance row by row
        for (int i = 1; i <= m; i++) {
            curr[0] = i;
            for (int j = 1; j <= n; j++) {
                if (s1.charAt(i - 1) == s2.charAt(j - 1)) {
                    curr[j] = prev[j - 1];
                } else {
                    curr[j] = 1 + Math.min(Math.min(prev[j], curr[j - 1]), prev[j - 1]);
                }
            }
            // Swap arrays for next iteration
            int[] temp = prev;
            prev = curr;
            curr = temp;
        }
        
        return prev[n];
    }

    private static String sha256Hex(String input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder(digest.length * 2);
        for (byte b : digest) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }
}

