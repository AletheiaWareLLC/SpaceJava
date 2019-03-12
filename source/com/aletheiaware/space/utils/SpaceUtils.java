/*
 * Copyright 2019 Aletheia Ware LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.aletheiaware.space.utils;

import com.aletheiaware.bc.BCProto.Block;
import com.aletheiaware.bc.BCProto.BlockEntry;
import com.aletheiaware.bc.BCProto.CompressionAlgorithm;
import com.aletheiaware.bc.BCProto.EncryptionAlgorithm;
import com.aletheiaware.bc.BCProto.Record;
import com.aletheiaware.bc.BCProto.Record.Access;
import com.aletheiaware.bc.BCProto.Reference;
import com.aletheiaware.bc.BCProto.SignatureAlgorithm;
import com.aletheiaware.bc.utils.BCUtils;
import com.aletheiaware.finance.FinanceProto.Subscription;
import com.aletheiaware.space.SpaceProto.Meta;
import com.google.protobuf.ByteString;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HttpsURLConnection;

public final class SpaceUtils {

    public static final String TAG = "Space";

    public static final String SPACE_HOST = "space.aletheiaware.com";
    public static final String SPACE_WEBSITE = "https://space.aletheiaware.com";

    public static final String FILE_CHANNEL_PREFIX = "Space-File-";
    public static final String META_CHANNEL_PREFIX = "Space-Meta-";
    public static final String PREVIEW_CHANNEL_PREFIX = "Space-Preview-";
    public static final String SHARE_CHANNEL_PREFIX = "Space-Share-";
    public static final String TAG_CHANNEL_PREFIX = "Space-Tag-";

    public static final String UNKNOWN_TYPE = "?/?";
    public static final String IMAGE_JPEG_TYPE = "image/jpeg";
    public static final String IMAGE_PNG_TYPE = "image/png";
    public static final String IMAGE_WEBP_TYPE = "image/webp";
    public static final String TEXT_PLAIN_TYPE = "text/plain";
    public static final String PROTOBUF_TYPE = "application/x-protobuf";
    public static final String VIDEO_MPEG_TYPE = "video/mpeg";

    public static final String DEFAULT_IMAGE_TYPE = "image/jpeg";
    public static final String DEFAULT_VIDEO_TYPE = "video/mpeg";

    public static final int PREVIEW_IMAGE_SIZE = 64;
    public static final int PREVIEW_TEXT_LENGTH = 64;

    public static final int SOCKET_TIMEOUT = 2 * 60 * 1000;// 2 minutes

    private SpaceUtils() {}

    public static String getFileType(File file) throws IOException {
        String type = null;
        try {
            type = Files.probeContentType(file.toPath());
        } catch (Exception e) {
            /* Ignored */
        }
        if (type == null || type.isEmpty()) {
            type = getTypeByExtension(file.getName());
        }
        return type;
    }

    public static String getTypeByExtension(String ext) {
        String type = null;
        if (ext.endsWith(".jpg") || ext.endsWith(".jpeg")) {
            type = IMAGE_JPEG_TYPE;
        } else if (ext.endsWith(".png")) {
            type = IMAGE_PNG_TYPE;
        } else if (ext.endsWith(".webp")) {
            type = IMAGE_WEBP_TYPE;
        } else if (ext.endsWith(".txt")) {
            type = TEXT_PLAIN_TYPE;
        } else if (ext.endsWith(".pb") || ext.endsWith(".proto")) {
            type = PROTOBUF_TYPE;
        } else if (ext.endsWith(".mpg") || ext.endsWith(".mpeg")  || ext.endsWith(".mp4")) {
            type = VIDEO_MPEG_TYPE;
        } else {
            type = UNKNOWN_TYPE;
            System.err.println("Unrecognized extention: " + ext);
        }
        return type;
    }

    public static boolean isVideo(String type) {
        return type.startsWith("video/");
    }

    public static boolean isImage(String type) {
        return type.startsWith("image/");
    }

    public static boolean isText(String type) {
        return type.startsWith("text/");
    }

    /**
     * Sorts a list of Record hashes by the timestamp of the Meta they map to.
     */
    public static void sort(List<ByteString> hashes, Map<ByteString, Long> timestamps, boolean chronologically) {
        Collections.sort(hashes, new Comparator<ByteString>() {
            @Override
            public int compare(ByteString b1, ByteString b2) {
                if (chronologically) {
                    return Long.compare(timestamps.get(b1), timestamps.get(b2));
                }
                return Long.compare(timestamps.get(b2), timestamps.get(b1));
            }
        });
    }

    public static Reference postRecord(String feature, Record record) throws IOException {
        URL url = new URL(SPACE_WEBSITE+"/mining/"+feature);
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        conn.setDoOutput(true);
        conn.setInstanceFollowRedirects(false);
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Connection", "Keep-Alive");
        conn.setRequestProperty("Keep-Alive", "timeout=60000");
        conn.setRequestProperty("Content-Type", PROTOBUF_TYPE);
        conn.setUseCaches(false);
        try (OutputStream o = conn.getOutputStream()) {
            record.writeDelimitedTo(o);
            o.flush();
        }
        int response = conn.getResponseCode();
        System.out.println("Response: " + response);
        if (response == HttpsURLConnection.HTTP_OK) {
            try (InputStream in = conn.getInputStream()) {
                return Reference.parseDelimitedFrom(in);
            }
        }
        return null;
    }

    /**
     * Register new customer
     */
    public static void register(String alias, String email, String paymentId) throws IOException {
        String params = "alias=" + URLEncoder.encode(alias, "utf-8")
                + "&stripeToken=" + URLEncoder.encode(paymentId, "utf-8")
                + "&stripeEmail=" + URLEncoder.encode(email, "utf-8");
        System.out.println("Params:" + params);
        byte[] data = params.getBytes(StandardCharsets.UTF_8);
        URL url = new URL(SPACE_WEBSITE+"/register");
        post(url, data);
    }

    /**
     * Subscribe customer to Remote Mining Service
     */
    public static void subscribe(String alias, String customerId) throws IOException {
        String params = "alias=" + URLEncoder.encode(alias, "utf-8")
                + "&customerId=" + URLEncoder.encode(customerId, "utf-8");
        System.out.println("Params:" + params);
        byte[] data = params.getBytes(StandardCharsets.UTF_8);
        URL url = new URL(SPACE_WEBSITE+"/subscribe");
        post(url, data);
    }

    public static void post(URL url, byte[] data) throws IOException {
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        conn.setDoOutput(true);
        conn.setInstanceFollowRedirects(false);
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        conn.setRequestProperty("charset", "utf-8");
        conn.setRequestProperty("Connection", "Keep-Alive");
        conn.setRequestProperty("Keep-Alive", "timeout=60000");
        conn.setRequestProperty("Content-Length", Integer.toString(data.length));
        conn.setUseCaches(false);
        try (OutputStream o = conn.getOutputStream()) {
            o.write(data);
            o.flush();
        }

        int response = conn.getResponseCode();
        System.out.println("Response: " + response);
        if (response == HttpsURLConnection.HTTP_OK) {
            try (InputStream in = conn.getInputStream()) {
                Scanner s = new Scanner(in);
                while (s.hasNextLine()) {
                    System.out.println(s.nextLine());
                }
            }
        }
    }

}
