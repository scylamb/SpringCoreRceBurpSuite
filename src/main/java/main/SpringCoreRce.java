package main;

import burp.IHttpRequestResponsePersisted;


public class SpringCoreRce {
    final String timestamp;
    final long length;
    final String url;
    final long status;
    final String method;
    final String result;
    final IHttpRequestResponsePersisted iHttpRequestResponse;

    public SpringCoreRce(String timestamp,String url, String method, long length, long status, String result, IHttpRequestResponsePersisted iHttpRequestResponse) {
        this.timestamp = timestamp;
        this.url = url;
        this.method = method;
        this.length = length;
        this.status = status;
        this.result = result;
        this.iHttpRequestResponse = iHttpRequestResponse;
    }
}
