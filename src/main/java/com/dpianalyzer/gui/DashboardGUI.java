package com.dpianalyzer.gui;

import com.dpianalyzer.alerts.AlertEngine;
import com.dpianalyzer.core.DPIEngine;
// import com.dpianalyzer.model.AppType;
import com.dpianalyzer.model.Flow;
import com.dpianalyzer.rules.RuleManager;
import com.dpianalyzer.util.PcapGenerator;
import org.jfree.chart.*;
import org.jfree.chart.plot.*;
import org.jfree.chart.renderer.category.BarRenderer;
import org.jfree.data.category.DefaultCategoryDataset;
import org.jfree.data.general.DefaultPieDataset;

import javax.swing.*;
import javax.swing.border.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.*;
import java.awt.*;
import java.awt.event.*;
import java.io.File;
import java.text.DecimalFormat;
// import java.time.ZoneId;
// import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

public class DashboardGUI extends JFrame {

    // ── Colors ─────────────────────────────────────────────────────
    private static final Color BG      = new Color(15, 17, 26);
    private static final Color CARD_BG = new Color(26, 29, 45);
    private static final Color ACCENT  = new Color(99, 179, 237);
    private static final Color SUCCESS = new Color(72, 199, 142);
    private static final Color DANGER  = new Color(252, 92, 101);
    private static final Color WARNING = new Color(253, 203, 110);
    private static final Color TEXT    = new Color(226, 232, 240);
    private static final Color MUTED   = new Color(113, 128, 150);

    // ── Engine ─────────────────────────────────────────────────────
    private DPIEngine engine;
    private RuleManager  ruleManager = new RuleManager();
    private AlertEngine  alertEngine = new AlertEngine();

    // ── Stat Cards ─────────────────────────────────────────────────
    private JLabel lbTotal, lbForwarded, lbDropped, lbFlows, lbAlerts, lbThroughput;

    // ── Charts ─────────────────────────────────────────────────────
    private final DefaultPieDataset<String>  pieDataset = new DefaultPieDataset<>();
    private final DefaultCategoryDataset     barDataset = new DefaultCategoryDataset();

    // ── Flow Table ─────────────────────────────────────────────────
    private static final String[] FLOW_COLS =
        {"Source IP","Destination","Port","App","SNI","Packets","Bytes","Status"};
    private DefaultTableModel flowTableModel;

    // ── Alert Feed ─────────────────────────────────────────────────
    private final DefaultListModel<String> alertListModel = new DefaultListModel<>();

    // ── State ──────────────────────────────────────────────────────
    private String loadedPcap = null;
    private final AtomicLong lastByteCount = new AtomicLong();
    private final ScheduledExecutorService uiTimer =
        Executors.newSingleThreadScheduledExecutor();
    private static final DecimalFormat FMT = new DecimalFormat("#,###");

    // ── Controls ───────────────────────────────────────────────────
    private JLabel  lbFilePath;
    private JButton btnStart, btnStop, btnGenerate;
    private JProgressBar progressBar;

    public DashboardGUI() {
        super("DPI Packet Analyzer — Live Dashboard");
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setSize(1300, 820);
        setMinimumSize(new Dimension(1100, 700));
        setLocationRelativeTo(null);
        getContentPane().setBackground(BG);
        setLayout(new BorderLayout(8, 8));

        add(buildHeader(), BorderLayout.NORTH);
        add(buildCenter(), BorderLayout.CENTER);

        wireAlertEngine(alertEngine);
        uiTimer.scheduleAtFixedRate(this::refreshStats, 500, 500, TimeUnit.MILLISECONDS);
    }

    // ── Wire alert listener ────────────────────────────────────────
    private void wireAlertEngine(AlertEngine ae) {
        ae.addListener(alert -> SwingUtilities.invokeLater(() -> {
            String entry = String.format("[%s] %s %s — %s",
                alert.formattedTime(), alert.severityIcon(), alert.title, alert.message);
            alertListModel.add(0, entry);
            // Keep max 300 entries — use remove(int) not removeLast()
            while (alertListModel.size() > 300) alertListModel.remove(alertListModel.size() - 1);
            updateAlertCount();
        }));
    }

    // ══════════════════════════════════════════════════════════════
    //  HEADER
    // ══════════════════════════════════════════════════════════════
    private JPanel buildHeader() {
        JPanel p = new JPanel(new BorderLayout(12, 0));
        p.setBackground(CARD_BG);
        p.setBorder(new EmptyBorder(12, 16, 12, 16));

        JLabel title = new JLabel("DPI Packet Analyzer");
        title.setFont(new Font("Segoe UI", Font.BOLD, 20));
        title.setForeground(ACCENT);

        JLabel sub = new JLabel("Deep Packet Inspection  |  Real-time Alerts  |  Live Dashboard");
        sub.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        sub.setForeground(MUTED);

        JPanel titles = new JPanel(new GridLayout(2, 1));
        titles.setOpaque(false);
        titles.add(title);
        titles.add(sub);

        lbFilePath = new JLabel("No file loaded — click Generate or Open PCAP");
        lbFilePath.setForeground(MUTED);
        lbFilePath.setFont(new Font("Monospaced", Font.PLAIN, 12));

        progressBar = new JProgressBar();
        progressBar.setIndeterminate(false);
        progressBar.setForeground(ACCENT);
        progressBar.setBackground(BG);
        progressBar.setPreferredSize(new Dimension(200, 5));
        progressBar.setBorderPainted(false);

        JPanel centerH = new JPanel(new BorderLayout(8, 4));
        centerH.setOpaque(false);
        centerH.add(lbFilePath, BorderLayout.CENTER);
        centerH.add(progressBar, BorderLayout.SOUTH);

        btnGenerate = styledBtn("Generate Test PCAP", ACCENT);
        JButton btnOpen = styledBtn("Open PCAP", new Color(72, 149, 239));
        btnStart = styledBtn("Start", SUCCESS);
        btnStop  = styledBtn("Stop",  DANGER);
        JButton btnRules = styledBtn("Rules", WARNING);

        btnStart.setEnabled(false);
        btnStop.setEnabled(false);

        btnGenerate.addActionListener(e -> generateTestPcap());
        btnOpen.addActionListener(e -> openPcap());
        btnStart.addActionListener(e -> startEngine());
        btnStop.addActionListener(e -> stopEngine());
        btnRules.addActionListener(e -> new RulesDialog(this, ruleManager).setVisible(true));

        JPanel btns = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        btns.setOpaque(false);
        btns.add(btnGenerate);
        btns.add(btnOpen);
        btns.add(btnStart);
        btns.add(btnStop);
        btns.add(btnRules);

        p.add(titles,  BorderLayout.WEST);
        p.add(centerH, BorderLayout.CENTER);
        p.add(btns,    BorderLayout.EAST);
        return p;
    }

    // ══════════════════════════════════════════════════════════════
    //  CENTER LAYOUT
    // ══════════════════════════════════════════════════════════════
    private JPanel buildCenter() {
        JPanel p = new JPanel(new BorderLayout(8, 8));
        p.setBackground(BG);
        p.setBorder(new EmptyBorder(0, 8, 8, 8));

        JPanel topRow = new JPanel(new BorderLayout(8, 0));
        topRow.setOpaque(false);
        topRow.add(buildStatCards(), BorderLayout.WEST);
        topRow.add(buildPieChart(),  BorderLayout.CENTER);
        topRow.add(buildAlertPanel(),BorderLayout.EAST);

        JPanel bottomRow = new JPanel(new BorderLayout(8, 0));
        bottomRow.setOpaque(false);
        bottomRow.add(buildBarChart(),  BorderLayout.WEST);
        bottomRow.add(buildFlowTable(), BorderLayout.CENTER);

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, topRow, bottomRow);
        split.setDividerLocation(280);
        split.setOpaque(false);
        split.setBackground(BG);
        split.setBorder(null);
        split.setDividerSize(6);

        p.add(split);
        return p;
    }

    // ── Stat Cards ────────────────────────────────────────────────
    private JPanel buildStatCards() {
        JPanel grid = new JPanel(new GridLayout(3, 2, 6, 6));
        grid.setOpaque(false);
        grid.setPreferredSize(new Dimension(320, 0));

        lbTotal      = statCard(grid, "Total Packets",  "0",      ACCENT);
        lbForwarded  = statCard(grid, "Forwarded",      "0",      SUCCESS);
        lbDropped    = statCard(grid, "Dropped",        "0",      DANGER);
        lbFlows      = statCard(grid, "Active Flows",   "0",      new Color(154, 117, 251));
        lbAlerts     = statCard(grid, "Alerts",         "0",      WARNING);
        lbThroughput = statCard(grid, "Throughput",     "0 B/s",  new Color(251, 130, 49));
        return grid;
    }

    private JLabel statCard(JPanel parent, String title, String initVal, Color accent) {
        JPanel card = new JPanel(new BorderLayout(4, 4));
        card.setBackground(CARD_BG);
        card.setBorder(new CompoundBorder(
            new LineBorder(accent.darker(), 1, true),
            new EmptyBorder(10, 12, 10, 12)));

        JLabel lbTitle = new JLabel(title);
        lbTitle.setForeground(MUTED);
        lbTitle.setFont(new Font("Segoe UI", Font.PLAIN, 11));

        JLabel lbVal = new JLabel(initVal);
        lbVal.setForeground(accent);
        lbVal.setFont(new Font("Segoe UI", Font.BOLD, 20));

        card.add(lbTitle, BorderLayout.NORTH);
        card.add(lbVal,   BorderLayout.CENTER);
        parent.add(card);
        return lbVal;
    }

    // ── Pie Chart ─────────────────────────────────────────────────
    private ChartPanel buildPieChart() {
        JFreeChart pieChart = ChartFactory.createPieChart(
            "Application Breakdown", pieDataset, true, true, false);
        styleChart(pieChart);

        PiePlot<?> plot = (PiePlot<?>) pieChart.getPlot();
        plot.setBackgroundPaint(CARD_BG);
        plot.setOutlineVisible(false);
        plot.setLabelFont(new Font("Segoe UI", Font.PLAIN, 11));
        plot.setLabelPaint(TEXT);
        plot.setSimpleLabels(true);

        ChartPanel cp = new ChartPanel(pieChart);
        cp.setBackground(CARD_BG);
        cp.setPreferredSize(new Dimension(350, 0));
        return cp;
    }

    // ── Alert Panel ───────────────────────────────────────────────
    private JPanel buildAlertPanel() {
        JPanel p = new JPanel(new BorderLayout(0, 6));
        p.setBackground(CARD_BG);
        p.setBorder(new CompoundBorder(
            new LineBorder(DANGER.darker(), 1),
            new EmptyBorder(8, 8, 8, 8)));
        p.setPreferredSize(new Dimension(310, 0));

        JLabel title = new JLabel("Live Alerts");
        title.setForeground(DANGER);
        title.setFont(new Font("Segoe UI", Font.BOLD, 13));

        JList<String> alertList = new JList<>(alertListModel);
        alertList.setBackground(BG);
        alertList.setForeground(TEXT);
        alertList.setFont(new Font("Monospaced", Font.PLAIN, 11));
        alertList.setCellRenderer(new AlertCellRenderer());

        JScrollPane scroll = new JScrollPane(alertList);
        scroll.setBackground(BG);
        scroll.setBorder(null);
        scroll.getViewport().setBackground(BG);

        p.add(title,  BorderLayout.NORTH);
        p.add(scroll, BorderLayout.CENTER);
        return p;
    }

    // ── Bar Chart ─────────────────────────────────────────────────
    private ChartPanel buildBarChart() {
        JFreeChart barChart = ChartFactory.createBarChart(
            "Packets by App", "Application", "Packets",
            barDataset, PlotOrientation.HORIZONTAL, false, true, false);
        styleChart(barChart);

        CategoryPlot plot = barChart.getCategoryPlot();
        plot.setBackgroundPaint(CARD_BG);
        plot.setOutlineVisible(false);
        plot.getRangeAxis().setLabelPaint(TEXT);
        plot.getRangeAxis().setTickLabelPaint(MUTED);
        plot.getDomainAxis().setTickLabelPaint(TEXT);
        plot.getDomainAxis().setTickLabelFont(new Font("Segoe UI", Font.PLAIN, 11));

        BarRenderer renderer = (BarRenderer) plot.getRenderer();
        renderer.setSeriesPaint(0, ACCENT);
        renderer.setDrawBarOutline(false);
        renderer.setShadowVisible(false);

        ChartPanel cp = new ChartPanel(barChart);
        cp.setBackground(CARD_BG);
        cp.setPreferredSize(new Dimension(350, 0));
        return cp;
    }

    // ── Flow Table ────────────────────────────────────────────────
    private JScrollPane buildFlowTable() {
        flowTableModel = new DefaultTableModel(FLOW_COLS, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        JTable flowTable = new JTable(flowTableModel);
        styleTable(flowTable);

        JScrollPane sp = new JScrollPane(flowTable);
        sp.setBackground(CARD_BG);
        sp.getViewport().setBackground(new Color(20, 23, 35));
        sp.setBorder(new TitledBorder(
            new LineBorder(ACCENT.darker()), "  Flow Table  ",
            TitledBorder.LEFT, TitledBorder.TOP,
            new Font("Segoe UI", Font.BOLD, 12), ACCENT));
        return sp;
    }

    private void styleTable(JTable t) {
        t.setBackground(new Color(20, 23, 35));
        t.setForeground(TEXT);
        t.setFont(new Font("Monospaced", Font.PLAIN, 12));
        t.setRowHeight(22);
        t.setShowGrid(false);
        t.setIntercellSpacing(new Dimension(0, 0));
        t.getTableHeader().setBackground(CARD_BG);
        t.getTableHeader().setForeground(ACCENT);
        t.getTableHeader().setFont(new Font("Segoe UI", Font.BOLD, 12));
        t.setDefaultRenderer(Object.class, new FlowTableRenderer());
    }

    private void styleChart(JFreeChart chart) {
        chart.setBackgroundPaint(CARD_BG);
        chart.getTitle().setPaint(TEXT);
        chart.getTitle().setFont(new Font("Segoe UI", Font.BOLD, 13));
        if (chart.getLegend() != null) {
            chart.getLegend().setBackgroundPaint(CARD_BG);
            chart.getLegend().setItemPaint(TEXT);
        }
    }

    // ══════════════════════════════════════════════════════════════
    //  ACTIONS
    // ══════════════════════════════════════════════════════════════
    private void generateTestPcap() {
        btnGenerate.setEnabled(false);
        btnGenerate.setText("Generating...");
        new SwingWorker<File, Void>() {
            @Override protected File doInBackground() throws Exception {
                File f = File.createTempFile("dpi_test_", ".pcap");
                PcapGenerator.generate(f.getAbsolutePath(), 500);
                return f;
            }
            @Override protected void done() {
                try {
                    File f = get();
                    loadedPcap = f.getAbsolutePath();
                    lbFilePath.setText(f.getName() + "  (500 synthetic packets)");
                    lbFilePath.setForeground(SUCCESS);
                    btnStart.setEnabled(true);
                    JOptionPane.showMessageDialog(DashboardGUI.this,
                        "Test PCAP generated!\n" + f.getAbsolutePath(),
                        "Done", JOptionPane.INFORMATION_MESSAGE);
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(DashboardGUI.this,
                        "Failed: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                }
                btnGenerate.setEnabled(true);
                btnGenerate.setText("Generate Test PCAP");
            }
        }.execute();
    }

    private void openPcap() {
        JFileChooser fc = new JFileChooser();
        fc.setFileFilter(new FileNameExtensionFilter("PCAP files (*.pcap)", "pcap"));
        if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            loadedPcap = fc.getSelectedFile().getAbsolutePath();
            lbFilePath.setText(fc.getSelectedFile().getName());
            lbFilePath.setForeground(ACCENT);
            btnStart.setEnabled(true);
        }
    }

    private void startEngine() {
        if (loadedPcap == null) return;
        alertListModel.clear();
        flowTableModel.setRowCount(0);
        lastByteCount.set(0);

        alertEngine = new AlertEngine();
        engine = new DPIEngine(4, ruleManager, alertEngine);
        wireAlertEngine(alertEngine);

        engine.setOnComplete(() -> SwingUtilities.invokeLater(() -> {
            progressBar.setIndeterminate(false);
            progressBar.setValue(100);
            btnStart.setEnabled(true);
            btnStop.setEnabled(false);
            refreshStats();
            JOptionPane.showMessageDialog(this,
                String.format("Analysis Complete!\n\nPackets : %s\nForwarded: %s\nDropped  : %s\nFlows   : %s\nAlerts  : %d",
                    FMT.format(engine.getTotalPackets()),
                    FMT.format(engine.getForwarded()),
                    FMT.format(engine.getDroppedPackets()),
                    FMT.format(engine.getFlowCount()),
                    alertEngine.getAlertCount()),
                "Analysis Complete", JOptionPane.INFORMATION_MESSAGE);
        }));

        btnStart.setEnabled(false);
        btnStop.setEnabled(true);
        progressBar.setIndeterminate(true);
        engine.startAsync(loadedPcap);
    }

    private void stopEngine() {
        if (engine != null) engine.stop();
        progressBar.setIndeterminate(false);
        btnStart.setEnabled(true);
        btnStop.setEnabled(false);
    }

    // ── Stats Refresh ─────────────────────────────────────────────
    private void refreshStats() {
        if (engine == null) return;
        SwingUtilities.invokeLater(() -> {
            long total   = engine.getTotalPackets();
            long dropped = engine.getDroppedPackets();
            long bytes   = engine.getTotalBytes();

            lbTotal.setText(FMT.format(total));
            lbForwarded.setText(FMT.format(engine.getForwarded()));
            lbDropped.setText(FMT.format(dropped));
            lbFlows.setText(FMT.format(engine.getFlowCount()));

            long delta = bytes - lastByteCount.getAndSet(bytes);
            lbThroughput.setText(formatBytes(delta * 2) + "/s");

            updatePieChart();
            updateBarChart();
            updateFlowTable();
        });
    }

    private void updateAlertCount() {
        int cnt = alertListModel.size();
        lbAlerts.setText(String.valueOf(cnt));
        lbAlerts.setForeground(cnt > 10 ? DANGER : cnt > 0 ? WARNING : TEXT);
    }

    private void updatePieChart() {
        if (engine == null) return;
        pieDataset.clear();
        engine.getAppStats().forEach((app, count) -> {
            if (count > 0) pieDataset.setValue(app.emoji + " " + app.displayName, count);
        });
    }

    private void updateBarChart() {
        if (engine == null) return;
        barDataset.clear();
        engine.getAppStats().entrySet().stream()
            .filter(e -> e.getValue() > 0)
            .sorted((a, b) -> Long.compare(b.getValue(), a.getValue()))
            .limit(10)
            .forEach(e -> barDataset.addValue(e.getValue(), "Packets", e.getKey().displayName));
    }

    private void updateFlowTable() {
        if (engine == null) return;
        List<Flow> flows = new ArrayList<>(engine.getFlows());
        flows.sort((a, b) -> Long.compare(b.getPacketCount(), a.getPacketCount()));
        flowTableModel.setRowCount(0);
        int max = Math.min(flows.size(), 100);
        for (int i = 0; i < max; i++) {
            Flow f = flows.get(i);
            flowTableModel.addRow(new Object[]{
                f.tuple.srcIp,
                f.tuple.dstIp,
                f.tuple.dstPort,
                f.appType.label(),
                f.sni.isEmpty() ? "-" : f.sni,
                FMT.format(f.getPacketCount()),
                formatBytes(f.getByteCount()),
                f.blocked ? "BLOCKED" : "OK"
            });
        }
    }

    // ── Helpers ───────────────────────────────────────────────────
    private JButton styledBtn(String text, Color color) {
        JButton b = new JButton(text);
        b.setBackground(color.darker().darker());
        b.setForeground(color);
        b.setFont(new Font("Segoe UI", Font.BOLD, 12));
        b.setBorder(new CompoundBorder(
            new LineBorder(color.darker(), 1, true),
            new EmptyBorder(6, 12, 6, 12)));
        b.setFocusPainted(false);
        b.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        b.addMouseListener(new MouseAdapter() {
            public void mouseEntered(MouseEvent e) { b.setBackground(color.darker()); }
            public void mouseExited(MouseEvent e)  { b.setBackground(color.darker().darker()); }
        });
        return b;
    }

    private static String formatBytes(long bytes) {
        if (bytes < 1024)          return bytes + " B";
        if (bytes < 1024 * 1024)   return String.format("%.1f KB", bytes / 1024.0);
        return String.format("%.1f MB", bytes / (1024.0 * 1024));
    }

    // ── Cell Renderers ────────────────────────────────────────────
    private class FlowTableRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(
                JTable t, Object val, boolean sel, boolean foc, int row, int col) {
            Component c = super.getTableCellRendererComponent(t, val, sel, foc, row, col);
            Object statusObj = t.getModel().getValueAt(row, 7);
            boolean blocked = statusObj != null && statusObj.toString().contains("BLOCKED");
            c.setBackground(sel ? ACCENT.darker().darker()
                : blocked ? new Color(60, 20, 20)
                : row % 2 == 0 ? new Color(20, 23, 35)
                : new Color(24, 27, 40));
            c.setForeground(blocked ? DANGER : TEXT);
            ((JLabel) c).setBorder(new EmptyBorder(2, 8, 2, 8));
            return c;
        }
    }

    private class AlertCellRenderer extends DefaultListCellRenderer {
        @Override
        public Component getListCellRendererComponent(
                JList<?> list, Object val, int idx, boolean sel, boolean focus) {
            JLabel lb = (JLabel) super.getListCellRendererComponent(list, val, idx, sel, focus);
            String s = val.toString();
            lb.setBackground(sel ? CARD_BG
                : s.contains("CRITICAL") ? new Color(50, 20, 20)
                : s.contains("WARNING")  ? new Color(50, 40, 10)
                : BG);
            lb.setForeground(s.contains("CRITICAL") ? DANGER
                : s.contains("WARNING") ? WARNING
                : TEXT);
            lb.setFont(new Font("Monospaced", Font.PLAIN, 11));
            lb.setBorder(new EmptyBorder(3, 6, 3, 6));
            return lb;
        }
    }
}
