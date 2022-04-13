package main;

import burp.BurpExtender;
import burp.ITab;

import javax.swing.*;
import java.awt.*;

public class MainPanel extends JTable implements ITab {
    private SpringCoreRceTableModel springCoreRceTableModel;

    public MainPanel(){
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));

        // main split pane
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

        // table of log entries
        springCoreRceTableModel = new SpringCoreRceTableModel();
        SpringCoreRceTable springCoreRceTable = new SpringCoreRceTable(springCoreRceTableModel);

        JScrollPane scrollPane = new JScrollPane(springCoreRceTable);

        splitPane.setLeftComponent(scrollPane);

        // tabs with request/response viewers
        JTabbedPane tabs = new JTabbedPane();
        tabs.setBorder(BorderFactory.createLineBorder(Color.black));
        tabs.addTab("Request", springCoreRceTable.getRequestViewer().getComponent());
        tabs.addTab("Response", springCoreRceTable.getResponseViewer().getComponent());
        splitPane.setRightComponent(tabs);

        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));


        controlPanel.setAlignmentX(0);
        add(controlPanel);
        add(splitPane);

        BurpExtender.callbacks.customizeUiComponent(this);
    }

    @Override
    public String getTabCaption() {
        return "SpringCoreRce";
    }

    @Override
    public Component getUiComponent() {
        return this;
    }

    public SpringCoreRceTableModel getSpringCoreRceTableModel() {
        return springCoreRceTableModel;
    }

}
