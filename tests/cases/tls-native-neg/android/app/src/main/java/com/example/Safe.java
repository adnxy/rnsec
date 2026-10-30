package com.example;

import android.webkit.SslErrorHandler;
import android.webkit.WebViewClient;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509TrustManager;

public class Safe {
    // Client certificates are not checked on the client side; only the server check matters
    static class ClientSideOnly implements X509TrustManager {
        private final X509TrustManager delegate;

        ClientSideOnly(X509TrustManager delegate) {
            this.delegate = delegate;
        }

        @Override
        public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) {
        }

        @Override
        public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType)
                throws java.security.cert.CertificateException {
            delegate.checkServerTrusted(chain, authType);
        }

        @Override
        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
            return delegate.getAcceptedIssuers();
        }
    }

    static final HostnameVerifier PINNED_HOST = new HostnameVerifier() {
        @Override
        public boolean verify(String hostname, SSLSession session) {
            return "api.example.com".equals(hostname);
        }
    };

    static class Client extends WebViewClient {
        @Override
        public void onReceivedSslError(android.webkit.WebView view, SslErrorHandler handler, android.net.http.SslError error) {
            handler.cancel();
        }
    }

    static class AskingClient extends WebViewClient {
        @Override
        public void onReceivedSslError(android.webkit.WebView view, SslErrorHandler handler, android.net.http.SslError error) {
            new android.app.AlertDialog.Builder(view.getContext())
                .setPositiveButton("Continue", (dialog, which) -> handler.proceed())
                .setNegativeButton("Cancel", (dialog, which) -> handler.cancel())
                .show();
        }
    }

    static class UrlCheckedClient extends WebViewClient {
        @Override
        public void onReceivedSslError(android.webkit.WebView view, SslErrorHandler handler, android.net.http.SslError error) {
            if (error.getUrl().startsWith("https://staging.example.com/")) {
                handler.proceed();
            } else {
                handler.cancel();
            }
        }
    }

    static void debugOnly(javax.net.ssl.HttpsURLConnection connection) {
        if (BuildConfig.DEBUG) {
            connection.setHostnameVerifier((hostname, session) -> true);
        }
    }
}
