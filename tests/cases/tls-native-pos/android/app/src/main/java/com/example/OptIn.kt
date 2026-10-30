package com.example

import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

fun socketFactory(validateCertificates: Boolean) {
    val context = SSLContext.getInstance("TLS")
    if (!validateCertificates) {
        val trustAll = arrayOf<TrustManager>(object : X509TrustManager {
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
            override fun checkClientTrusted(certs: Array<X509Certificate>, authType: String) {}
            override fun checkServerTrusted(certs: Array<X509Certificate>, authType: String) {}
        })
        context.init(null, trustAll, null)
    } else {
        context.init(null, null, null)
    }
}

val verifier = javax.net.ssl.HostnameVerifier { _, _ -> true }

class SslClient : android.webkit.WebViewClient() {
    override fun onReceivedSslError(view: android.webkit.WebView?, handler: android.webkit.SslErrorHandler?, error: android.net.http.SslError?) {
        if (allowSelfSigned) {
            handler?.proceed()
        } else {
            handler?.cancel()
        }
    }
}
