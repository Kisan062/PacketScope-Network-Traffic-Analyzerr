package com.packetscope;

import com.packetscope.gui.DashboardGUI;
import com.packetscope.util.DebugTest;

import javax.swing.*;

public class Main {

    public static void main(String[] args) throws Exception {
        // Run debug test if --debug flag passed
        if (args.length > 0 && args[0].equals("--debug")) {
            DebugTest.runTest();
            return;
        }

        UIManager.put("Panel.background",              new java.awt.Color(15, 17, 26));
        UIManager.put("OptionPane.background",         new java.awt.Color(26, 29, 45));
        UIManager.put("OptionPane.messageForeground",  new java.awt.Color(226, 232, 240));
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception ignored) {}

        SwingUtilities.invokeLater(() -> {
            DashboardGUI gui = new DashboardGUI();
            gui.setVisible(true);
        });
    }
}
