package com.dpianalyzer.gui;

import com.dpianalyzer.model.AppType;
import com.dpianalyzer.rules.RuleManager;

import javax.swing.*;
import javax.swing.border.*;
import java.awt.*;

/**
 * Dialog for managing blocking rules at runtime.
 * Users can block/unblock IPs, apps, and domains while the engine runs.
 */
public class RulesDialog extends JDialog {

    private static final Color BG      = new Color(15, 17, 26);
    private static final Color CARD_BG = new Color(26, 29, 45);
    private static final Color ACCENT  = new Color(99, 179, 237);
    private static final Color DANGER  = new Color(252, 92, 101);
    private static final Color WARNING = new Color(253, 203, 110);
    private static final Color SUCCESS = new Color(72, 199, 142);
    private static final Color TEXT    = new Color(226, 232, 240);
    private static final Color MUTED   = new Color(113, 128, 150);

    private final RuleManager rules;

    // IP
    private JTextField tfIp;
    private DefaultListModel<String> ipModel = new DefaultListModel<>();

    // App
    private JComboBox<AppType> cbApp;
    private DefaultListModel<String> appModel = new DefaultListModel<>();

    // Domain
    private JTextField tfDomain;
    private DefaultListModel<String> domainModel = new DefaultListModel<>();

    public RulesDialog(Frame parent, RuleManager rules) {
        super(parent, "🛡 Blocking Rules Manager", true);
        this.rules = rules;
        setSize(560, 520);
        setLocationRelativeTo(parent);
        setResizable(false);
        initUI();
        loadCurrentRules();
    }

    private void initUI() {
        JPanel root = new JPanel(new BorderLayout(0, 0));
        root.setBackground(BG);
        root.setBorder(new EmptyBorder(12, 12, 12, 12));

        JLabel title = new JLabel("Manage Blocking Rules  (changes apply immediately)");
        title.setForeground(ACCENT);
        title.setFont(new Font("Segoe UI", Font.BOLD, 14));
        title.setBorder(new EmptyBorder(0, 0, 10, 0));

        JTabbedPane tabs = new JTabbedPane();
        tabs.setBackground(CARD_BG);
        tabs.setForeground(TEXT);
        tabs.setFont(new Font("Segoe UI", Font.BOLD, 13));
        tabs.addTab("🔴 Block IP",     buildIpPanel());
        tabs.addTab("📵 Block App",    buildAppPanel());
        tabs.addTab("🌐 Block Domain", buildDomainPanel());

        JButton btnClose = new JButton("Close");
        btnClose.setBackground(CARD_BG);
        btnClose.setForeground(TEXT);
        btnClose.setFont(new Font("Segoe UI", Font.BOLD, 12));
        btnClose.setBorder(new CompoundBorder(new LineBorder(MUTED, 1, true), new EmptyBorder(6,16,6,16)));
        btnClose.addActionListener(e -> dispose());

        JButton btnClear = new JButton("Clear All Rules");
        btnClear.setBackground(CARD_BG);
        btnClear.setForeground(DANGER);
        btnClear.setFont(new Font("Segoe UI", Font.BOLD, 12));
        btnClear.setBorder(new CompoundBorder(new LineBorder(DANGER.darker(), 1, true), new EmptyBorder(6,16,6,16)));
        btnClear.addActionListener(e -> {
            if (JOptionPane.showConfirmDialog(this, "Clear ALL rules?", "Confirm", JOptionPane.YES_NO_OPTION) == 0) {
                rules.clearAll();
                ipModel.clear(); appModel.clear(); domainModel.clear();
            }
        });

        JPanel footer = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        footer.setOpaque(false);
        footer.add(btnClear);
        footer.add(btnClose);

        root.add(title,   BorderLayout.NORTH);
        root.add(tabs,    BorderLayout.CENTER);
        root.add(footer,  BorderLayout.SOUTH);
        add(root);
    }

    private JPanel buildIpPanel() {
        JPanel p = rulePanel();
        tfIp = new JTextField();
        styleField(tfIp, "e.g. 192.168.1.50");

        JButton btnAdd = addBtn("Block IP");
        btnAdd.addActionListener(e -> {
            String ip = tfIp.getText().trim();
            if (!ip.isEmpty()) {
                rules.blockIp(ip);
                if (!ipModel.contains(ip)) ipModel.addElement(ip);
                tfIp.setText("");
            }
        });

        JList<String> list = styledList(ipModel);
        JButton btnRemove = removeBtn("Unblock Selected");
        btnRemove.addActionListener(e -> {
            String sel = list.getSelectedValue();
            if (sel != null) { rules.unblockIp(sel); ipModel.removeElement(sel); }
        });

        p.add(inputRow(tfIp, btnAdd), BorderLayout.NORTH);
        p.add(new JScrollPane(list),  BorderLayout.CENTER);
        p.add(btnRemove,               BorderLayout.SOUTH);
        return p;
    }

    private JPanel buildAppPanel() {
        JPanel p = rulePanel();
        cbApp = new JComboBox<>(AppType.values());
        cbApp.setBackground(CARD_BG);
        cbApp.setForeground(TEXT);
        cbApp.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        cbApp.setRenderer(new DefaultListCellRenderer() {
            public Component getListCellRendererComponent(JList<?> l, Object v, int i, boolean s, boolean f) {
                JLabel lb = (JLabel) super.getListCellRendererComponent(l, v, i, s, f);
                lb.setText(v instanceof AppType a ? a.label() : v.toString());
                lb.setBackground(s ? ACCENT.darker().darker() : CARD_BG);
                lb.setForeground(TEXT);
                return lb;
            }
        });

        JButton btnAdd = addBtn("Block App");
        btnAdd.addActionListener(e -> {
            AppType app = (AppType) cbApp.getSelectedItem();
            if (app != null) {
                rules.blockApp(app);
                if (!appModel.contains(app.label())) appModel.addElement(app.label());
            }
        });

        JList<String> list = styledList(appModel);
        JButton btnRemove = removeBtn("Unblock Selected");
        btnRemove.addActionListener(e -> {
            String sel = list.getSelectedValue();
            if (sel != null) {
                for (AppType a : AppType.values()) {
                    if (a.label().equals(sel)) { rules.unblockApp(a); break; }
                }
                appModel.removeElement(sel);
            }
        });

        p.add(inputRow(cbApp, btnAdd), BorderLayout.NORTH);
        p.add(new JScrollPane(list),   BorderLayout.CENTER);
        p.add(btnRemove,                BorderLayout.SOUTH);
        return p;
    }

    private JPanel buildDomainPanel() {
        JPanel p = rulePanel();
        tfDomain = new JTextField();
        styleField(tfDomain, "e.g. tiktok (substring match)");

        JButton btnAdd = addBtn("Block Domain");
        btnAdd.addActionListener(e -> {
            String d = tfDomain.getText().trim();
            if (!d.isEmpty()) {
                rules.blockDomain(d);
                if (!domainModel.contains(d)) domainModel.addElement(d);
                tfDomain.setText("");
            }
        });

        JList<String> list = styledList(domainModel);
        JButton btnRemove = removeBtn("Unblock Selected");
        btnRemove.addActionListener(e -> {
            String sel = list.getSelectedValue();
            if (sel != null) { rules.unblockDomain(sel); domainModel.removeElement(sel); }
        });

        p.add(inputRow(tfDomain, btnAdd), BorderLayout.NORTH);
        p.add(new JScrollPane(list),      BorderLayout.CENTER);
        p.add(btnRemove,                   BorderLayout.SOUTH);
        return p;
    }

    private void loadCurrentRules() {
        rules.getBlockedIps().forEach(ipModel::addElement);
        rules.getBlockedApps().forEach(a -> appModel.addElement(a.label()));
        rules.getBlockedDomains().forEach(domainModel::addElement);
    }

    // ── Helpers ───────────────────────────────────────────────────
    private JPanel rulePanel() {
        JPanel p = new JPanel(new BorderLayout(6, 6));
        p.setBackground(BG);
        p.setBorder(new EmptyBorder(10, 10, 10, 10));
        return p;
    }

    private JPanel inputRow(JComponent input, JButton btn) {
        JPanel p = new JPanel(new BorderLayout(6, 0));
        p.setOpaque(false);
        p.setBorder(new EmptyBorder(0, 0, 6, 0));
        p.add(input, BorderLayout.CENTER);
        p.add(btn,   BorderLayout.EAST);
        return p;
    }

    private void styleField(JTextField f, String placeholder) {
        f.setBackground(CARD_BG);
        f.setForeground(TEXT);
        f.setCaretColor(ACCENT);
        f.setFont(new Font("Monospaced", Font.PLAIN, 13));
        f.setBorder(new CompoundBorder(new LineBorder(MUTED, 1), new EmptyBorder(4,8,4,8)));
        f.setToolTipText(placeholder);
    }

    private JButton addBtn(String label) {
        JButton b = new JButton(label);
        b.setBackground(DANGER.darker().darker());
        b.setForeground(DANGER);
        b.setFont(new Font("Segoe UI", Font.BOLD, 12));
        b.setBorder(new CompoundBorder(new LineBorder(DANGER.darker(), 1, true), new EmptyBorder(5,12,5,12)));
        b.setFocusPainted(false);
        return b;
    }

    private JButton removeBtn(String label) {
        JButton b = new JButton(label);
        b.setBackground(CARD_BG);
        b.setForeground(WARNING);
        b.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        b.setBorder(new CompoundBorder(new LineBorder(WARNING.darker(), 1, true), new EmptyBorder(4,10,4,10)));
        b.setFocusPainted(false);
        return b;
    }

    private JList<String> styledList(DefaultListModel<String> model) {
        JList<String> list = new JList<>(model);
        list.setBackground(CARD_BG);
        list.setForeground(TEXT);
        list.setFont(new Font("Monospaced", Font.PLAIN, 13));
        list.setSelectionBackground(DANGER.darker().darker());
        list.setSelectionForeground(DANGER);
        list.setBorder(new EmptyBorder(4,6,4,6));
        return list;
    }
}
