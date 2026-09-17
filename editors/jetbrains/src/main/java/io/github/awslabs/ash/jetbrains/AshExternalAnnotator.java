// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains;

import com.intellij.lang.annotation.AnnotationHolder;
import com.intellij.lang.annotation.ExternalAnnotator;
import com.intellij.lang.annotation.HighlightSeverity;
import com.intellij.openapi.editor.Document;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.util.TextRange;
import com.intellij.openapi.vfs.VirtualFile;
import com.intellij.psi.PsiFile;
import java.nio.file.Path;
import java.util.List;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/**
 * Wires ASH's findings into the editor's annotation pass.
 *
 * <p>IDE GLUE. It is listed in coverage-exclusions.json with a line budget, and the budget is
 * the point: every decision this class could make has been moved into {@link AshScanService}
 * and {@link AshAnnotationPlanner}, which are measured, so if this file grows the exclusion
 * stops being honest and the coverage gate says so.
 *
 * <p>WHY ExternalAnnotator AND NOT LocalInspectionTool
 *
 * <p>An inspection runs on the EDT's read action and is expected to return quickly from an
 * in-memory analysis. This spawns a process and scans a repository. {@code ExternalAnnotator}
 * is the platform's contract for exactly that: {@link #doAnnotate} runs off the read action,
 * on a background thread, and is the only place a long-running external tool may be invoked.
 * Using an inspection would freeze the editor for the length of a scan.
 *
 * <p>WHY THE SCAN IS SCOPED TO THE PROJECT AND NOT THE FILE
 *
 * <p>ASH scans a tree. Several of its scanners are about relationships between files -- a
 * dependency graph, an IaC template and the files it references -- so a single-file scan would
 * report less than a real one, and quietly. The cost is that this is not something to run on
 * every keystroke, which is why {@link #collectInformation} only proceeds for a saved file.
 */
public final class AshExternalAnnotator
        extends ExternalAnnotator<
                AshExternalAnnotator.Request, AshExternalAnnotator.Findings> {

    /** What {@link #collectInformation} gathers on the EDT for {@link #doAnnotate} to use. */
    record Request(Project project, Path projectRoot, Path filePath, String documentText) {}

    /** What {@link #doAnnotate} produces for {@link #apply} to write out. */
    record Findings(List<AshAnnotationPlanner.PlannedAnnotation> annotations, String error) {}

    @Override
    public @Nullable Request collectInformation(
            @NotNull PsiFile file, @NotNull com.intellij.openapi.editor.Editor editor, boolean hasErrors) {
        if (!AshSettings.getInstance().enabled) {
            return null;
        }
        VirtualFile virtualFile = file.getVirtualFile();
        Project project = file.getProject();
        String basePath = project.getBasePath();
        if (virtualFile == null || basePath == null || !virtualFile.isInLocalFileSystem()) {
            return null;
        }
        Document document = editor.getDocument();
        return new Request(
                project,
                Path.of(basePath),
                Path.of(virtualFile.getPath()),
                document.getText());
    }

    @Override
    public @Nullable Findings doAnnotate(Request request) {
        if (request == null) {
            return null;
        }
        AshScanPlan plan =
                new AshScanPlan(
                        AshExecutable.resolve(AshSettings.getInstance().executablePath),
                        request.projectRoot(),
                        AshOutputDirectory.forProject(request.projectRoot()));
        AshScanService.Result result = AshScanService.withRealEnvironment().scan(plan);
        if (result.failed()) {
            return new Findings(List.of(), result.error());
        }
        String relative = request.projectRoot().relativize(request.filePath()).toString();
        return new Findings(
                AshAnnotationPlanner.plan(result.findings(), relative, request.documentText()),
                null);
    }

    @Override
    public void apply(
            @NotNull PsiFile file, Findings findings, @NotNull AnnotationHolder holder) {
        if (findings == null) {
            return;
        }
        if (findings.error() != null) {
            // A banner on the file rather than a log line. The failure this plugin exists to
            // remove is a security tool that reports nothing for a reason the user never
            // sees, so the message goes where they are already looking.
            holder.newAnnotation(HighlightSeverity.WARNING, findings.error())
                    .fileLevel()
                    .create();
            return;
        }
        for (AshAnnotationPlanner.PlannedAnnotation planned : findings.annotations()) {
            holder.newAnnotation(toHighlightSeverity(planned.severity()), planned.message())
                    .range(new TextRange(planned.startOffset(), planned.endOffset()))
                    .create();
        }
    }

    private static HighlightSeverity toHighlightSeverity(AshSeverity severity) {
        switch (severity) {
            case ERROR:
                return HighlightSeverity.ERROR;
            case WEAK_WARNING:
                return HighlightSeverity.WEAK_WARNING;
            case INFORMATION:
                return HighlightSeverity.INFORMATION;
            case WARNING:
            default:
                return HighlightSeverity.WARNING;
        }
    }
}
