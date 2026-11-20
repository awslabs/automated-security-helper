// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains.ui

import com.intellij.remoterobot.RemoteRobot
import io.github.awslabs.ash.jetbrains.snapshot.Snapshots
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.BeforeClass
import org.junit.FixMethodOrder
import org.junit.Test
import org.junit.runners.MethodSorters
import java.awt.image.BufferedImage
import java.io.ByteArrayInputStream
import java.nio.file.Files
import java.nio.file.Path
import java.util.Base64
import javax.imageio.ImageIO

/**
 * Screenshots of the plugin's UI in a real IDE, compared pixel for pixel with the committed PNGs.
 *
 * The IDE is the one runIdeForUiTests starts (see build.gradle.kts and ui-test-in-container.sh),
 * with this build's plugin installed, on a project holding the planted-secret fixture, and with
 * the ASH executable set to a stub that replays the captured real exit-1 run, with one warning and
 * one note added to its SARIF (src/uiTest/scan/README.txt says why). The suite clicks
 * nothing it does not have to: it invokes the plugin's own menu action through the IDE's action
 * system, as the Tools menu does, and then renders each scene.
 *
 * SCENES, the plugin's UI surfaces that have a look as well as words:
 *  1. the incomplete-scan notification balloon;
 *  2. the editor with the five findings highlighted (three errors, a warning and a note, so each
 *     level's highlight style is in the pixels) and the problem counts in its corner;
 *  3. the error tooltip for the finding under the caret (Ctrl+F1, the same popup a hover shows);
 *  4. the Problems tool window's File tab listing the findings. The plugin registers no tool
 *     window of its own, so this is where its findings appear as a tool window;
 *  5. Settings | Tools | ASH.
 * There is no report view to capture: the plugin has none.
 *
 * HOW A SCENE IS RENDERED. The component is painted into an offscreen image inside the IDE
 * (Component.paint on the EDT), not grabbed from the screen. A screen grab would also capture a
 * cursor, a window overlapping the component, or a fade animation part-way through; painting the
 * component gives only its own pixels. Each scene is painted until three consecutive paints agree,
 * so a scene caught mid-layout is retried rather than compared, and only then compared, exactly,
 * with the baseline.
 *
 * WHAT IS PINNED, and checked rather than assumed: the environment scene below renders the IDE
 * build, theme, fonts, antialiasing, scale and screen as text and compares it with a committed
 * text snapshot, so a drift in any of them fails with a readable diff before a pixel is compared.
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
class VisualSnapshotTest {

    companion object {
        private lateinit var robot: RemoteRobot
        private val rendered: Path = Path.of(requireNotNull(System.getProperty(Snapshots.ACTUAL_PROPERTY))).resolve("rendered")

        /** Shared by every script: finding components and painting them. */
        private val PRELUDE = """
            var ash = {};
            ash.project = function () {
              var ps = com.intellij.openapi.project.ProjectManager.getInstance().getOpenProjects();
              return ps.length > 0 ? ps[0] : null;
            };
            ash.find = function (root, pred) {
              if (pred(root)) return root;
              if (root instanceof java.awt.Container) {
                var kids = root.getComponents();
                for (var i = 0; i < kids.length; i++) { var f = ash.find(kids[i], pred); if (f != null) return f; }
              }
              return null;
            };
            ash.findShowing = function (pred) {
              var ws = java.awt.Window.getWindows();
              for (var i = 0; i < ws.length; i++) {
                if (ws[i].isShowing()) { var f = ash.find(ws[i], pred); if (f != null) return f; }
              }
              return null;
            };
            ash.is = function (c, name) { return String(c.getClass().getName()) == name; };
            ash.text = function (c) { try { return c.getText ? String(c.getText()) : ""; } catch (e) { return ""; } };
            ash.png = function (c) {
              var img = new java.awt.image.BufferedImage(c.getWidth(), c.getHeight(), java.awt.image.BufferedImage.TYPE_INT_ARGB);
              var g = img.createGraphics();
              try { c.paint(g); } finally { g.dispose(); }
              var out = new java.io.ByteArrayOutputStream();
              javax.imageio.ImageIO.write(img, "png", out);
              return java.util.Base64.getEncoder().encodeToString(out.toByteArray());
            };
            ash.wir = function (f) {
              var result = null;
              com.intellij.openapi.application.WriteIntentReadAction.run(new java.lang.Runnable({ run: function () { result = f(); } }));
              return result;
            };
            ash.editor = function () {
              return com.intellij.openapi.fileEditor.FileEditorManager.getInstance(ash.project()).getSelectedTextEditor();
            };
        """.trimIndent()

        /**
         * Runs [script] in the IDE and returns its completion value as a string.
         *
         * The value is passed through `eval` and converted to a java.lang.String there, because a
         * JavaScript string reaches the robot's serializer as one of Rhino's own string classes,
         * which the client side cannot deserialize.
         */
        private fun js(script: String, edt: Boolean = true): String {
            val literal = buildString {
                append('"')
                for (ch in script) {
                    when (ch) {
                        '\\' -> append("\\\\")
                        '"' -> append("\\\"")
                        '\n' -> append("\\n")
                        '\r' -> append("\\r")
                        else -> append(ch)
                    }
                }
                append('"')
            }
            return robot.callJs("$PRELUDE\nvar __result = eval($literal);\nnew java.lang.String(String(__result));", edt)
        }

        private fun waitFor(what: String, timeoutMs: Long = 120_000, condition: () -> Boolean) {
            val deadline = System.currentTimeMillis() + timeoutMs
            var lastError: Exception? = null
            while (true) {
                val ok = try {
                    condition()
                } catch (e: Exception) {
                    // Expected while the IDE is still starting; reported if it never stops.
                    lastError = e
                    false
                }
                if (ok) return
                if (System.currentTimeMillis() > deadline) {
                    throw AssertionError("timed out after ${timeoutMs}ms waiting for $what; last error: $lastError", lastError)
                }
                Thread.sleep(250)
            }
        }

        @BeforeClass
        @JvmStatic
        fun startScene() {
            robot = RemoteRobot(requireNotNull(System.getProperty("ash.ui.robot")))
            val projectDir = requireNotNull(System.getProperty("ash.ui.project")?.takeIf { it.isNotEmpty() }) {
                "ash.ui.project is not set; run the suite through ui-test-in-container.sh"
            }

            waitFor("the project to open and indexing to finish", 300_000) {
                js(
                    """
                    var p = ash.project();
                    String(p != null && p.isInitialized() && !com.intellij.openapi.project.DumbService.isDumb(p)
                      && com.intellij.openapi.wm.WindowManager.getInstance().getFrame(p) != null
                      && com.intellij.openapi.wm.WindowManager.getInstance().getFrame(p).isShowing());
                    """,
                ) == "true"
            }

            // The frame at a fixed place and size, every tool window hidden, and the fixture open.
            js(
                """
                var p = ash.project();
                var frame = com.intellij.openapi.wm.WindowManager.getInstance().getFrame(p);
                frame.setExtendedState(java.awt.Frame.NORMAL);
                frame.setBounds(0, 0, 1600, 1000);
                frame.validate();
                var twm = com.intellij.openapi.wm.ToolWindowManager.getInstance(p);
                var ids = twm.getToolWindowIds();
                for (var i = 0; i < ids.length; i++) { var tw = twm.getToolWindow(ids[i]); if (tw != null && tw.isVisible()) tw.hide(null); }
                var vf = com.intellij.openapi.vfs.LocalFileSystem.getInstance().refreshAndFindFileByPath("$projectDir/leak.py");
                com.intellij.openapi.fileEditor.FileEditorManager.getInstance(p).openFile(vf, true);
                "ok";
                """,
            )
            waitFor("the fixture to open in an editor") { js("String(ash.editor() != null)") == "true" }

            // The scan, through the plugin's own action, exactly as Tools | Run ASH Security Scan.
            js(
                """
                var am = com.intellij.openapi.actionSystem.ActionManager.getInstance();
                var frame = com.intellij.openapi.wm.WindowManager.getInstance().getFrame(ash.project());
                am.tryToExecute(am.getAction("io.github.awslabs.ash.jetbrains.AshScanAction"), null, frame.getRootPane(), "MainMenu", true);
                "ok";
                """,
            )
            waitFor("the incomplete-scan notification") { js("String(ash.findShowing(function (c) { return ash.is(c, 'javax.swing.JLabel') && ash.text(c).indexOf('ASH scan incomplete') >= 0; }) != null)") == "true" }
            // All five, whatever severity each was given: the scenes are where a change to a
            // level's look is caught, so the wait counts findings and leaves severity and style
            // to the pixels (and to InspectionSnapshotTest).
            waitFor("the five ASH findings to be highlighted") {
                js(
                    """
                    ash.wir(function () {
                      var p = ash.project();
                      var doc = ash.editor().getDocument();
                      var infos = com.intellij.codeInsight.daemon.impl.DaemonCodeAnalyzerImpl.getHighlights(doc, com.intellij.lang.annotation.HighlightSeverity.INFORMATION, p);
                      var n = 0;
                      for (var i = 0; i < infos.size(); i++) { var d = infos.get(i).getDescription(); if (d != null && String(d).indexOf("ASH [") == 0) n++; }
                      var psi = com.intellij.psi.PsiDocumentManager.getInstance(p).getPsiFile(doc);
                      return String(n == 5 && com.intellij.codeInsight.daemon.impl.DaemonCodeAnalyzerEx.getInstanceEx(p).isErrorAnalyzingFinished(psi));
                    });
                    """,
                ) == "true"
            }
        }

        /**
         * Paints the component [locate] finds until three paints agree, then decodes it.
         *
         * @param locate a JS expression that evaluates to the component, or null while it is absent.
         */
        private fun render(locate: String): BufferedImage {
            // Three equal paints, 500 ms apart: longer than the IDE's toolbar update interval, so a
            // button whose enabled state is still being recomputed cannot pass for settled.
            var previous: String? = null
            var same = 0
            repeat(60) {
                val png = js("var c = ($locate); c == null ? '' : ash.png(c);")
                same = if (png.isNotEmpty() && png == previous) same + 1 else 0
                if (same == 2) return ImageIO.read(ByteArrayInputStream(Base64.getDecoder().decode(png)))
                previous = png.ifEmpty { null }
                Thread.sleep(500)
            }
            fail("the scene located by `$locate` never painted the same pixels three times in a row")
            error("unreachable")
        }

        /** Compares a scene with its baseline, and keeps its raw pixels for the cross-run digest. */
        private fun assertScene(name: String, image: BufferedImage) {
            val argb = Snapshots.argb(image)
            Files.createDirectories(rendered)
            val pixels = IntArray(argb.width * argb.height)
            argb.getRGB(0, 0, argb.width, argb.height, pixels, 0, argb.width)
            val bytes = java.nio.ByteBuffer.allocate(8 + pixels.size * 4).putInt(argb.width).putInt(argb.height)
            pixels.forEach { bytes.putInt(it) }
            Files.write(rendered.resolve("$name.rgba"), bytes.array())
            Snapshots.assertImageMatches(VisualSnapshotTest::class.java, name, argb)
        }
    }

    @Test
    fun scene0Environment() {
        val environment = js(
            """
            var info = com.intellij.openapi.application.ApplicationInfo.getInstance();
            var ui = com.intellij.ide.ui.UISettings.getInstance();
            var laf = com.intellij.ide.ui.LafManager.getInstance().getCurrentUIThemeLookAndFeel();
            var scheme = com.intellij.openapi.editor.colors.EditorColorsManager.getInstance().getGlobalScheme();
            var screen = java.awt.Toolkit.getDefaultToolkit().getScreenSize();
            var gc = java.awt.GraphicsEnvironment.getLocalGraphicsEnvironment().getDefaultScreenDevice().getDefaultConfiguration();
            var frame = com.intellij.openapi.wm.WindowManager.getInstance().getFrame(ash.project());
            var label = new javax.swing.JLabel();
            [
              "ide: " + info.getBuild().asString() + " (" + info.getFullApplicationName() + ")",
              "jre: " + java.lang.System.getProperty("java.runtime.version"),
              "theme: " + laf.getId() + " (" + laf.getName() + ")",
              "new ui: " + com.intellij.ui.ExperimentalUI.isNewUI(),
              "ui font: " + label.getFont().getFamily() + " " + label.getFont().getSize(),
              "ui font override: " + ui.getOverrideLafFonts() + " " + ui.getFontFace() + " " + ui.getFontSize2D(),
              "editor font: " + scheme.getEditorFontName() + " " + scheme.getEditorFontSize2D() + ", line spacing " + scheme.getLineSpacing(),
              "editor scheme: " + scheme.getName(),
              "antialiasing: ide " + ui.getIdeAAType() + ", editor " + ui.getEditorAAType(),
              "ui scale: " + com.intellij.ui.scale.JBUIScale.scale(1.0) + ", system scale " + com.intellij.ui.scale.JBUIScale.sysScale(),
              "screen: " + screen.width + "x" + screen.height + ", device transform scale " + gc.getDefaultTransform().getScaleX(),
              "screen resolution: " + java.awt.Toolkit.getDefaultToolkit().getScreenResolution() + " dpi",
              "frame: " + frame.getX() + "," + frame.getY() + " " + frame.getWidth() + "x" + frame.getHeight(),
              "locale: " + java.util.Locale.getDefault() + ", time zone " + java.util.TimeZone.getDefault().getID()
            ].join("\n");
            """,
        )
        Snapshots.assertMatches(VisualSnapshotTest::class.java, "environment", environment)
    }

    @Test
    fun scene1IncompleteScanNotification() {
        val balloon = render(
            """
            ash.findShowing(function (c) {
              return ash.is(c, 'com.intellij.ui.BalloonImpl${'$'}MyComponent')
                && ash.find(c, function (k) { return ash.is(k, 'javax.swing.JLabel') && ash.text(k).indexOf('ASH scan incomplete') >= 0; }) != null;
            })
            """,
        )
        assertScene("incomplete-scan-notification", balloon)
    }

    @Test
    fun scene2EditorWithFindings() {
        js(
            """
            ash.wir(function () {
              var e = ash.editor();
              e.getCaretModel().moveToOffset(0);
              e.getScrollingModel().scrollVertically(0);
              e.getScrollingModel().scrollHorizontally(0);
              return "ok";
            });
            """,
        )
        assertScene("editor-findings", render("ash.editor().getComponent()"))
    }

    @Test
    fun scene3ErrorTooltip() {
        js(
            """
            ash.wir(function () {
              var e = ash.editor();
              e.getCaretModel().moveToOffset(e.getDocument().getLineStartOffset(1) + 30);
              var am = com.intellij.openapi.actionSystem.ActionManager.getInstance();
              am.tryToExecute(am.getAction("ShowErrorDescription"), null, e.getContentComponent(), "EditorPopup", true);
              return "ok";
            });
            """,
        )
        assertScene(
            "error-tooltip",
            render("ash.findShowing(function (c) { return ash.is(c, 'com.intellij.codeInsight.hint.LineTooltipRenderer${'$'}1MyPanel'); })"),
        )
        // Closed again, so it cannot overlap a later scene.
        js(
            """
            com.intellij.codeInsight.hint.HintManager.getInstance().hideAllHints();
            ash.wir(function () { ash.editor().getCaretModel().moveToOffset(0); return "ok"; });
            """,
        )
    }

    @Test
    fun scene4ProblemsToolWindow() {
        js(
            """
            var tw = com.intellij.openapi.wm.ToolWindowManager.getInstance(ash.project()).getToolWindow("Problems View");
            tw.show(null);
            var cm = tw.getContentManager();
            cm.setSelectedContent(cm.getContent(0));
            "ok";
            """,
        )
        // The file's row and its five findings.
        waitFor("the Problems view to list the five findings") {
            js(
                """
                var tw = com.intellij.openapi.wm.ToolWindowManager.getInstance(ash.project()).getToolWindow("Problems View");
                var tree = ash.find(tw.getComponent(), function (c) { return c instanceof javax.swing.JTree; });
                String(tree != null && tree.getRowCount() == 6);
                """,
            ) == "true"
        }
        // The view selects a row on its own, at a moment that depends on when the tree's model
        // finished loading, and a selected row also changes which toolbar buttons are enabled.
        // Measured: one run rendered the first finding selected and the next did not, and
        // clearing the selection did not hold because the view selected the row again
        // afterwards. So the first finding is selected here, which is the state the view
        // converges on either way, and the scene is rendered once that selection has held.
        js(
            """
            var tw = com.intellij.openapi.wm.ToolWindowManager.getInstance(ash.project()).getToolWindow("Problems View");
            ash.find(tw.getComponent(), function (c) { return c instanceof javax.swing.JTree; }).setSelectionRow(1);
            "ok";
            """,
        )
        waitFor("the first finding to stay selected") {
            js(
                """
                var tw = com.intellij.openapi.wm.ToolWindowManager.getInstance(ash.project()).getToolWindow("Problems View");
                var tree = ash.find(tw.getComponent(), function (c) { return c instanceof javax.swing.JTree; });
                var rows = tree.getSelectionRows();
                String(rows != null && rows.length == 1 && rows[0] == 1 && !tree.hasFocus());
                """,
            ) == "true"
        }
        assertScene(
            "problems-tool-window",
            render("com.intellij.openapi.wm.ToolWindowManager.getInstance(ash.project()).getToolWindow('Problems View').getComponent()"),
        )
        js("com.intellij.openapi.wm.ToolWindowManager.getInstance(ash.project()).getToolWindow('Problems View').hide(null); 'ok';")
    }

    @Test
    fun scene5SettingsPage() {
        // showSettingsDialog is modal, so it is queued rather than called: the call would not
        // return until the dialog closed.
        js(
            """
            var p = ash.project();
            com.intellij.openapi.application.ApplicationManager.getApplication().invokeLater(new java.lang.Runnable({ run: function () {
              com.intellij.openapi.options.ShowSettingsUtil.getInstance().showSettingsDialog(p, "ASH");
            }}));
            "ok";
            """,
        )
        val page = "ash.findShowing(function (c) { return ash.is(c, 'com.intellij.ui.components.JBLabel') && ash.text(c) == 'ASH executable:'; })"
        waitFor("Settings | Tools | ASH to open") { js("String(($page) != null)") == "true" }
        try {
            assertScene("settings-page", render("($page).getParent()"))
        } finally {
            js(
                """
                var dialog = com.intellij.openapi.ui.DialogWrapper.findInstance($page);
                if (dialog != null) dialog.close(com.intellij.openapi.ui.DialogWrapper.CANCEL_EXIT_CODE);
                "ok";
                """,
            )
        }
        assertEquals("the settings dialog must be closed", "false", js("String(($page) != null)"))
    }
}
