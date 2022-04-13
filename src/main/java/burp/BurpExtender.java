package burp;

import main.MainPanel;
import main.SpringCoreRceMain;
import main.Utils;

import java.io.PrintWriter;


public class BurpExtender implements IBurpExtender {
    private PrintWriter stdout;
    private IExtensionHelpers helpers;
    public static IBurpExtenderCallbacks callbacks;
    private final String EXTENDER_NAME = "SpringCoreRCE";
    private String EXTENDER_VERSION = "1.0.0";

    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        BurpExtender.callbacks = callbacks;
        Utils.setBurpPresent(callbacks);


        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        callbacks.setExtensionName(EXTENDER_NAME);
        this.helpers = callbacks.getHelpers();


        MainPanel panel = new MainPanel();
        Utils.setPanel(panel);
        callbacks.addSuiteTab(panel);
        callbacks.registerScannerCheck(new SpringCoreRceMain());

//        callbacks.registerScannerCheck(new SpringCoreRceMain()); // 为自定义上下文菜单项注册工厂

        banner();

    }

    private void banner() {
        this.stdout.println("===================================");
        this.stdout.println(String.format("%s loaded success", EXTENDER_NAME));
        this.stdout.println(String.format("version: %s", EXTENDER_VERSION));
        this.stdout.println("===================================");
    }

}