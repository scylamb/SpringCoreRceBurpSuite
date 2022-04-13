package main;

import burp.*;


import javax.swing.*;

public class SpringCoreRceTable extends JTable implements IMessageEditorController {
    private IHttpRequestResponse currentlyDisplayedItem;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private SpringCoreRceTableModel springCoreRceTableModel;

    SpringCoreRceTable(SpringCoreRceTableModel springCoreRceTableModel){
        super(springCoreRceTableModel);
        this.springCoreRceTableModel = springCoreRceTableModel;
        this.requestViewer = BurpExtender.callbacks.createMessageEditor(this, false);
        this.responseViewer = BurpExtender.callbacks.createMessageEditor(this, false);
        setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
//        getColumnModel().getColumn(0).setMinWidth(150);
//        getColumnModel().getColumn(1).setMinWidth(100);
//        getColumnModel().getColumn(2).setMinWidth(100);
//        getColumnModel().getColumn(3).setMinWidth(100);
//        getColumnModel().getColumn(4).setPreferredWidth(1100);
//        getColumnModel().getColumn(5).setMinWidth(100);
//        getColumnModel().getColumn(6).setMinWidth(100);
        setAutoCreateRowSorter(true);

    }

//    public SpringCoreRceTable(springCoreRceTableModel springCoreRceTableModel) {
//    }


    @Override
    public IHttpService getHttpService() {
        return currentlyDisplayedItem.getHttpService();
    }

    @Override
    public byte[] getRequest() {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return currentlyDisplayedItem.getResponse();
    }

    // JTable
    @Override
    public void changeSelection(int rowIndex, int columnIndex, boolean toggle, boolean extend) {
        SpringCoreRce springCoreRce = this.springCoreRceTableModel.getSpringCoreRceList().get(convertRowIndexToModel(rowIndex));
        requestViewer.setMessage(springCoreRce.iHttpRequestResponse.getRequest(), true);
        responseViewer.setMessage(springCoreRce.iHttpRequestResponse.getResponse(), false);
        currentlyDisplayedItem = springCoreRce.iHttpRequestResponse;

        super.changeSelection(rowIndex, columnIndex, toggle, extend);
    }

    IMessageEditor getRequestViewer() {

        return requestViewer;
    }

    IMessageEditor getResponseViewer() {

        return responseViewer;
    }
}
