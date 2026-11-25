package com.example;

import android.webkit.WebView;
import javax.crypto.Cipher;

public class Main {
    void configure(WebView view) throws Exception {
        view.getSettings().setAllowFileAccess(true);
        String password = "not-a-real-password-fixture";
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
    }
}
