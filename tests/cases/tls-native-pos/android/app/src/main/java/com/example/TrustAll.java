package com.example;

import android.webkit.SslErrorHandler;
import android.webkit.WebViewClient;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509TrustManager;
import org.apache.http.conn.ssl.SSLSocketFactory;

public class TrustAll {
    static final X509TrustManager TRUST_ALL = new X509TrustManager() {
        @Override
        public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) {
        }

        @Override
        public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) {
            // accept everything
        }

        @Override
        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
            return new java.security.cert.X509Certificate[]{};
        }
    };

    static final HostnameVerifier ANY_HOST = new HostnameVerifier() {
        @Override
        public boolean verify(String hostname, SSLSession session) {
            return true;
        }
    };

    static HostnameVerifier lambdaVerifier() {
        HostnameVerifier v = (hostname, session) -> true;
        return v;
    }

    static void legacy(SSLSocketFactory factory) {
        factory.setHostnameVerifier(SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
    }

    static class Client extends WebViewClient {
        @Override
        public void onReceivedSslError(android.webkit.WebView view, SslErrorHandler handler, android.net.http.SslError error) {
            handler.proceed();
        }
    }
}
