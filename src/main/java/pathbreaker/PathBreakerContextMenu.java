package pathbreaker;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.http.message.HttpRequestResponse;

import javax.swing.*;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class PathBreakerContextMenu implements ContextMenuItemsProvider {

    private final MontoyaApi api;
    private final PathBreakerTab tab;

    public PathBreakerContextMenu(MontoyaApi api, PathBreakerTab tab) {
        this.api = api;
        this.tab = tab;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> items = new ArrayList<>();

        // Try to get a request from the event
        Optional<HttpRequestResponse> maybeReqResp = Optional.empty();

        // Check selected requests in proxy/target/etc.
        if (!event.selectedRequestResponses().isEmpty()) {
            maybeReqResp = Optional.of(event.selectedRequestResponses().get(0));
        }
        // Fall back to message editor context
        else if (event.messageEditorRequestResponse().isPresent()) {
            maybeReqResp = Optional.of(
                event.messageEditorRequestResponse().get().requestResponse()
            );
        }

        if (maybeReqResp.isPresent()) {
            final HttpRequestResponse reqResp = maybeReqResp.get();
            // Only show menu item if there's an actual request
            if (reqResp.request() != null) {
                JMenuItem sendItem = new JMenuItem("Send to PathBreaker");
                sendItem.addActionListener(e -> {
                    tab.setTarget(reqResp);
                    // Switch Burp to the PathBreaker tab
                    api.userInterface().swingUtils().suiteFrame().toFront();
                });
                items.add(sendItem);
            }
        }

        return items;
    }
}
