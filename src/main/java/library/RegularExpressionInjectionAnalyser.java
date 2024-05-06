package library;

import analysis.AnalysisSettings;
import analysis.NFAAnalyserFlattening;
import analysis.NFAAnalyserInterface;
import nfa.NFAGraph;
import regexcompiler.MyPattern;

import java.util.List;
import java.util.concurrent.*;
import java.util.regex.Matcher;
import java.util.regex.PatternSyntaxException;

// inspired by the regex static analysis project, link to original class below
// https://github.com/NicolaasWeideman/RegexStaticAnalysis/blob/master/src/main/java/analysis/driver/AnalysisDriverStdOut.java

public class RegularExpressionInjectionAnalyser implements Runnable {
    private static final String ERROR_MESSAGE_NO_TERMINATE = "Executor could not be terminated";
    private static final String ERROR_MESSAGE_BACKTRACKING_NOT_SUPPORTED = "Backtracking not supported";

    private final String pattern;
    private final NFAAnalyserInterface analyser;
    private NFAAnalyserInterface.AnalysisResultsType analysisResultsType;

    private RegularExpressionInjectionAnalyser(String pattern, NFAAnalyserInterface analyser) {
        this.pattern = pattern
                // named groups fail the analysis, so we remove them
                .replaceAll("\\(\\?<[^>]+>", "(")
                // this pattern is not recognized by the analysis, it always represents a single character, so we can
                // substitute it with anything
                .replaceAll("\\\\p\\{[^}]+}", Matcher.quoteReplacement("\\$"));

        this.analyser = analyser;
    }

    public static boolean isVulnerable(String pattern) throws ExecutionException {
        NFAAnalyserInterface analyser = new NFAAnalyserFlattening(
                AnalysisSettings.PriorityRemovalStrategy.UNPRIORITISE);
        RegularExpressionInjectionAnalyser regexAnalyser = new RegularExpressionInjectionAnalyser(pattern, analyser);

        ExecutorService executor = Executors.newSingleThreadExecutor();
        Future<?> future = executor.submit(regexAnalyser);
        executor.shutdown();
        try {
            future.get(5, TimeUnit.SECONDS);
            return List.of(NFAAnalyserInterface.AnalysisResultsType.EDA, NFAAnalyserInterface.AnalysisResultsType.IDA)
                    .contains(regexAnalyser.analysisResultsType);
        } catch (TimeoutException e) {
            terminateExecutor(executor);
            return true;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ExecutionException(e);
        } catch (ExecutionException e) {
            if (e.getCause() instanceof PatternSyntaxException) {
                PatternSyntaxException pse = (PatternSyntaxException) e.getCause();
                if (pse.getPattern().matches("^\\\\\\d$")) {
                    throw new ExecutionException(new UnsupportedOperationException(ERROR_MESSAGE_BACKTRACKING_NOT_SUPPORTED));
                }
            }
            throw e;
        } finally {
            if (!executor.isTerminated()) {
                executor.shutdownNow();
            }
        }
    }

    private static void terminateExecutor(ExecutorService executor) throws ExecutionException {
        try {
            if (!executor.isTerminated()) {
                executor.shutdownNow();
                if (!executor.awaitTermination(2, TimeUnit.SECONDS)) {
                    throw new IllegalThreadStateException(ERROR_MESSAGE_NO_TERMINATE);
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ExecutionException(e);
        }
    }

    @Override
    public void run() {
        try {
            NFAGraph analysisGraph = MyPattern.toNFAGraph(this.pattern, AnalysisSettings.NFAConstruction.JAVA);

            this.analysisResultsType = this.analyser.containsEDA(analysisGraph);
            if (this.analysisResultsType == NFAAnalyserInterface.AnalysisResultsType.NO_EDA) {
                this.analysisResultsType = this.analyser.containsIDA(analysisGraph);
                if (!List.of(
                                NFAAnalyserInterface.AnalysisResultsType.IDA,
                                NFAAnalyserInterface.AnalysisResultsType.NO_IDA,
                                NFAAnalyserInterface.AnalysisResultsType.ANALYSIS_FAILED,
                                NFAAnalyserInterface.AnalysisResultsType.TIMEOUT_IN_IDA)
                        .contains(this.analysisResultsType)) {
                    throw new RuntimeException(
                            "Unexpected Analysis Results Type after IDA analysis: " + this.analysisResultsType);
                }
            } else if (!List.of(
                            NFAAnalyserInterface.AnalysisResultsType.EDA,
                            NFAAnalyserInterface.AnalysisResultsType.ANALYSIS_FAILED,
                            NFAAnalyserInterface.AnalysisResultsType.TIMEOUT_IN_EDA)
                    .contains(this.analysisResultsType)) {
                throw new RuntimeException(
                        "Unexpected Analysis Results Type after EDA analysis: " + this.analysisResultsType);
            }
        } catch (Exception | OutOfMemoryError e) {
            this.analysisResultsType = NFAAnalyserInterface.AnalysisResultsType.ANALYSIS_FAILED;
            throw e;
        }
    }
}
