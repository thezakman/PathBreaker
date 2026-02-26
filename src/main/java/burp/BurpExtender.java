package burp;

import burp.ui.PathBreakerTab;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * PathBreaker – a professional path and header fuzzing extension for Burp Suite.
 *
 * <p>Entry point registered via the {@code burp.IBurpExtender} SPI.
 * Implements {@link ITab} to add the PathBreaker panel to the Burp UI and
 * {@link IContextMenuFactory} to expose right-click "Send to PathBreaker" menu
 * items on any request in Proxy History, Repeater, etc.</p>
 */
public class BurpExtender implements IBurpExtender, ITab, IContextMenuFactory {

    private IBurpExtenderCallbacks callbacks;
    private PathBreakerTab mainTab;

    // -------------------------------------------------------------------------
    // IBurpExtender
    // -------------------------------------------------------------------------

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        callbacks.setExtensionName("PathBreaker");
        callbacks.registerContextMenuFactory(this);

        SwingUtilities.invokeLater(() -> {
            mainTab = new PathBreakerTab(callbacks, callbacks.getHelpers());
            callbacks.addSuiteTab(BurpExtender.this);
            callbacks.printOutput("[PathBreaker] Extension loaded successfully.");
        });
    }

    // -------------------------------------------------------------------------
    // ITab
    // -------------------------------------------------------------------------

    @Override
    public String getTabCaption() {
        return "PathBreaker";
    }

    @Override
    public Component getUiComponent() {
        return mainTab;
    }

    // -------------------------------------------------------------------------
    // IContextMenuFactory
    // -------------------------------------------------------------------------

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menu = new ArrayList<>();
        IHttpRequestResponse[] messages = invocation.getSelectedMessages();
        if (messages == null || messages.length == 0) return menu;

        JMenuItem toPath = new JMenuItem("Send to PathBreaker – Path Fuzzer");
        toPath.addActionListener(e -> {
            mainTab.sendToPathFuzzer(messages[0]);
            callbacks.printOutput("[PathBreaker] Request sent to Path Fuzzer.");
        });

        JMenuItem toHeader = new JMenuItem("Send to PathBreaker – Header Fuzzer");
        toHeader.addActionListener(e -> {
            mainTab.sendToHeaderFuzzer(messages[0]);
            callbacks.printOutput("[PathBreaker] Request sent to Header Fuzzer.");
        });

        menu.add(toPath);
        menu.add(toHeader);
        return menu;
    }
}
