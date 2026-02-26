package burp.ui;

import burp.model.FuzzResult;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Table model for displaying fuzzing results with colour-coded status codes.
 */
public class ResultsTableModel extends AbstractTableModel {

    private static final String[] COLUMNS = {"#", "Value", "Status", "Length", "Time (ms)", "Notes"};
    private static final int[] COLUMN_WIDTHS = {40, 350, 70, 80, 80, 200};

    private final List<FuzzResult> results = new ArrayList<>();

    public void addResult(FuzzResult result) {
        results.add(result);
        int row = results.size() - 1;
        fireTableRowsInserted(row, row);
    }

    public void clear() {
        int size = results.size();
        if (size > 0) {
            results.clear();
            fireTableRowsDeleted(0, size - 1);
        }
    }

    public FuzzResult getResult(int row) {
        return results.get(row);
    }

    public List<FuzzResult> getResults() {
        return new ArrayList<>(results);
    }

    @Override public int getRowCount()    { return results.size(); }
    @Override public int getColumnCount() { return COLUMNS.length; }
    @Override public String getColumnName(int col) { return COLUMNS[col]; }

    @Override
    public Object getValueAt(int row, int col) {
        FuzzResult r = results.get(row);
        switch (col) {
            case 0: return r.getIndex();
            case 1: return r.getValue();
            case 2: return r.getStatusCode() == 0 ? "ERR" : r.getStatusCode();
            case 3: return r.getResponseLength();
            case 4: return r.getResponseTime();
            case 5: return r.getNotes();
            default: return "";
        }
    }

    /** Apply preferred column widths and the colour-coded row renderer to a JTable. */
    public void applyTo(JTable table) {
        for (int i = 0; i < COLUMN_WIDTHS.length; i++) {
            table.getColumnModel().getColumn(i).setPreferredWidth(COLUMN_WIDTHS[i]);
        }
        table.setDefaultRenderer(Object.class, new StatusCellRenderer());
        table.setRowHeight(20);
    }

    // -------------------------------------------------------------------------
    // Renderer
    // -------------------------------------------------------------------------

    private static class StatusCellRenderer extends DefaultTableCellRenderer {

        private static final Color GREEN  = new Color(0xC8, 0xE6, 0xC9);
        private static final Color YELLOW = new Color(0xFF, 0xF9, 0xC4);
        private static final Color ORANGE = new Color(0xFF, 0xE0, 0xB2);
        private static final Color RED    = new Color(0xFF, 0xCC, 0xBC);
        private static final Color DARK   = new Color(0xEF, 0x9A, 0x9A);

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                boolean selected, boolean focus, int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, selected, focus, row, column);
            if (!selected) {
                ResultsTableModel model = (ResultsTableModel) table.getModel();
                int status = model.getResult(row).getStatusCode();
                if (status >= 200 && status < 300) {
                    c.setBackground(GREEN);
                } else if (status >= 300 && status < 400) {
                    c.setBackground(YELLOW);
                } else if (status >= 400 && status < 500) {
                    c.setBackground(ORANGE);
                } else if (status >= 500) {
                    c.setBackground(RED);
                } else if (status == 0) {
                    c.setBackground(DARK);
                } else {
                    c.setBackground(table.getBackground());
                }
            }
            return c;
        }
    }
}
