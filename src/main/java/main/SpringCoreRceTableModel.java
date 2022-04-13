package main;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

public class SpringCoreRceTableModel extends AbstractTableModel {
    private final List<SpringCoreRce> springCoreRceList = new ArrayList();

    public int getRowCount() {
        return springCoreRceList.size();
    }

    public int getColumnCount() {
        return 6;
    }

    @Override
    public String getColumnName(int column) {
        switch (column) {
            case 0:
                return "Time";
            case 1:
                return "Request URL";
            case 2:
                return "Method";
            case 3:
                return "Length";
            case 4:
                return "HTTP Status";
            case 5:
                return "Result";
            default:
                return "";
        }
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        switch (columnIndex) {
            case 0:
            case 2:
            case 1:
            case 3:
            case 5:
                return String.class;
            case 4:
                return Short.class;
            default:
                return Object.class;
        }
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        SpringCoreRce springCoreRce = springCoreRceList.get(rowIndex);

        switch (columnIndex) {
            case 0:
                return springCoreRce.timestamp;
            case 1:
                return springCoreRce.url.toString();
            case 2:
                return springCoreRce.method;
            case 3:
                return springCoreRce.length;
            case 4:
                return springCoreRce.status;
            case 5:
                return springCoreRce.result;
            default:
                return "";
        }
    }

    public List<SpringCoreRce> getSpringCoreRceList() {
        return springCoreRceList;
    }
}
