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

import com.aletheiaware.bc.BC.Channel;
import com.aletheiaware.bc.BC.Channel.RecordCallback;
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
import com.aletheiaware.space.SpaceProto.Share;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;

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
import java.util.Arrays;
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
    public static final String SPACE_HOST_TEST = "test-space.aletheiaware.com";
    public static final String SPACE_WEBSITE = "https://space.aletheiaware.com";
    public static final String SPACE_WEBSITE_TEST = "https://test-space.aletheiaware.com";

    public static final String SPACE_PREFIX_FILE = "Space-File-";
    public static final String SPACE_PREFIX_META = "Space-Meta-";
    public static final String SPACE_PREFIX_PREVIEW = "Space-Preview-";
    public static final String SPACE_PREFIX_SHARE = "Space-Share-";
    public static final String SPACE_PREFIX_TAG = "Space-Tag-";

    public static final String UNKNOWN_TYPE = "?/?";
    public static final String IMAGE_JPEG_TYPE = "image/jpeg";
    public static final String IMAGE_PNG_TYPE = "image/png";
    public static final String IMAGE_WEBP_TYPE = "image/webp";
    public static final String TEXT_PLAIN_TYPE = "text/plain";
    public static final String PROTOBUF_TYPE = "application/x-protobuf";
    public static final String VIDEO_MPEG_TYPE = "video/mpeg";

    public static final String DEFAULT_IMAGE_TYPE = "image/jpeg";
    public static final String DEFAULT_VIDEO_TYPE = "video/mpeg";

    public static final int PREVIEW_IMAGE_SIZE = 128;
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
                long t1 = 0L;
                if (timestamps.containsKey(b1)) {
                    t1 = timestamps.get(b1);
                }
                long t2 = 0L;
                if (timestamps.containsKey(b2)) {
                    t2 = timestamps.get(b2);
                }
                if (chronologically) {
                    return Long.compare(t1, t2);
                }
                return Long.compare(t2, t1);
            }
        });
    }

    public static void readMetas(InetAddress host, File cache, String alias, KeyPair keys, byte[] metaRecordHash, RecordCallback callback) throws IOException {
        final Channel metas = new Channel(SPACE_PREFIX_META + alias, BCUtils.THRESHOLD_STANDARD, cache, host);
        try {
            metas.sync();
        } catch (IOException | NoSuchAlgorithmException e) {
            /* Ignored */
            e.printStackTrace();
        }
        metas.read(alias, keys, metaRecordHash, callback);
    }

    public static void readFiles(InetAddress host, File cache, String alias, KeyPair keys, byte[] fileRecordHash, RecordCallback callback) throws IOException {
        final Channel files = new Channel(SPACE_PREFIX_FILE + alias, BCUtils.THRESHOLD_STANDARD, cache, host);
        files.read(alias, keys, fileRecordHash, callback);
    }

    public static void readPreviews(InetAddress host, File cache, String alias, KeyPair keys, byte[] previewRecordHash, byte[] metaRecordHash, RecordCallback previewCallback) throws IOException {
        final Channel previews = new Channel(SPACE_PREFIX_PREVIEW + new String(BCUtils.encodeBase64URL(metaRecordHash)), BCUtils.THRESHOLD_STANDARD, cache, host);
        previews.read(alias, keys, previewRecordHash, previewCallback);
    }

    public static void readShares(InetAddress host, File cache, String alias, KeyPair keys, byte[] shareRecordHash, byte[] metaRecordHash, RecordCallback metaCallback, RecordCallback fileCallback) throws IOException {
        final Channel shares = new Channel(SPACE_PREFIX_SHARE + alias, BCUtils.THRESHOLD_STANDARD, cache, host);
        try {
            shares.sync();
        } catch (IOException | NoSuchAlgorithmException e) {
            /* Ignored */
            e.printStackTrace();
        }
        shares.read(alias, keys, shareRecordHash, new RecordCallback() {
            @Override
            public boolean onRecord(ByteString blockHash, Block block, BlockEntry blockEntry, byte[] key, byte[] payload) {
                try {
                    Share share = Share.newBuilder().mergeFrom(payload).build();
                    // System.out.println("Share: " + share);
                    Reference sharedMetaReference = share.getMetaReference();
                    if (metaRecordHash == null || Arrays.equals(sharedMetaReference.getRecordHash().toByteArray(), metaRecordHash)) {
                        // System.out.println("Shared Reference: " + new String(BCUtils.encodeBase64URL(sharedMetaReference.getRecordHash().toByteArray())));
                        try {
                            Block sharedMetaBlock = BCUtils.getBlock(host, sharedMetaReference);
                            // System.out.println("Shared Block: " + sharedMetaBlock);
                            if (sharedMetaBlock != null) {
                                for (BlockEntry sharedMetaBlockEntry : sharedMetaBlock.getEntryList()) {
                                    // System.out.println("Shared Record: " + sharedMetaBlockEntry.getRecord());
                                    if (sharedMetaReference.getRecordHash().equals(sharedMetaBlockEntry.getRecordHash())) {
                                        Record sharedMetaRecord = sharedMetaBlockEntry.getRecord();
                                        if (metaCallback != null) {
                                            try {
                                                byte[] metaKey = share.getMetaKey().toByteArray();
                                                byte[] decryptedPayload = BCUtils.decryptAES(metaKey, sharedMetaRecord.getPayload().toByteArray());
                                                metaCallback.onRecord(sharedMetaReference.getBlockHash(), sharedMetaBlock, sharedMetaBlockEntry, metaKey, decryptedPayload);
                                            } catch (BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException ex) {
                                                /* Ignored */
                                                ex.printStackTrace();
                                            }
                                        }
                                        if (fileCallback != null) {
                                            List<ByteString> chunkKeys = share.getChunkKeyList();
                                            List<Reference> chunkReferences = sharedMetaRecord.getReferenceList();
                                            int count = Math.min(chunkKeys.size(), chunkReferences.size());
                                            for (int i = 0; i < count; i++) {
                                                Reference chunkReference = chunkReferences.get(i);
                                                try {
                                                    Block chunkBlock = BCUtils.getBlock(host, chunkReference);
                                                    if (chunkBlock != null) {
                                                        for (BlockEntry chunkEntry : chunkBlock.getEntryList()) {
                                                            if (chunkReference.getRecordHash().equals(chunkEntry.getRecordHash())) {
                                                                Record chunkRecord = chunkEntry.getRecord();
                                                                // System.out.println("Shared Chunk: " + chunkRecord);
                                                                try {
                                                                    byte[] chunkKey = chunkKeys.get(i).toByteArray();
                                                                    byte[] decryptedPayload = BCUtils.decryptAES(chunkKey, chunkRecord.getPayload().toByteArray());
                                                                    fileCallback.onRecord(chunkReference.getBlockHash(), chunkBlock, chunkEntry, chunkKey, decryptedPayload);
                                                                } catch (BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException ex) {
                                                                    /* Ignored */
                                                                    ex.printStackTrace();
                                                                }
                                                            }
                                                        }
                                                    }
                                                } catch (IOException ex) {
                                                    /* Ignored */
                                                    ex.printStackTrace();
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        } catch (IOException e) {
                            /* Ignored */
                            e.printStackTrace();
                        }
                    }
                } catch (InvalidProtocolBufferException e) {
                    e.printStackTrace();
                }
                return true;
            }
        });
    }

    public static Reference postRecord(String host, String feature, Record record) throws IOException {
        URL url = new URL(host+"/mining/"+feature);
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        conn.setDoOutput(true);
        conn.setInstanceFollowRedirects(false);
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Connection", "Keep-Alive");
        conn.setRequestProperty("Keep-Alive", "timeout=60000");
        conn.setRequestProperty("Content-Type", PROTOBUF_TYPE);
        conn.setUseCaches(false);
        OutputStream out = conn.getOutputStream();
        record.writeDelimitedTo(out);
        out.flush();
        InputStream err = conn.getErrorStream();
        InputStream in = conn.getInputStream();
        int response = conn.getResponseCode();
        System.out.println("Response: " + response);
        Reference result = null;
        if (response == HttpsURLConnection.HTTP_OK) {
            result = Reference.parseDelimitedFrom(in);
        } else {
            StringBuilder sb = new StringBuilder();
            Scanner s = new Scanner(err);
            while (s.hasNextLine()) {
                sb.append(s.nextLine());
                sb.append("\n");
            }
            System.err.println("Error: " + sb.toString());
        }
        if (result == null) {
            // Disconnect in case of TCP Keep Alive issues
            out.close();
            in.close();
            conn.disconnect();
        }
        return result;
    }

    /**
     * Register new customer
     */
    public static String register(String host, String alias, String email, String paymentId) throws IOException {
        String params = "api=1&alias=" + URLEncoder.encode(alias, "utf-8")
                + "&stripeToken=" + URLEncoder.encode(paymentId, "utf-8")
                + "&stripeEmail=" + URLEncoder.encode(email, "utf-8");
        System.out.println("Params:" + params);
        byte[] data = params.getBytes(StandardCharsets.UTF_8);
        URL url = new URL(host+"/space-register");
        return postForID(url, data);
    }

    /**
     * Subscribe customer to Remote Mining Service
     */
    public static String subscribe(String host, String alias, String customerId) throws IOException {
        String params = "api=1&alias=" + URLEncoder.encode(alias, "utf-8")
                + "&customerId=" + URLEncoder.encode(customerId, "utf-8");
        System.out.println("Params:" + params);
        byte[] data = params.getBytes(StandardCharsets.UTF_8);
        URL url = new URL(host+"/space-subscribe");
        return postForID(url, data);
    }

    public static String postForID(URL url, byte[] data) throws IOException {
        HttpsURLConnection conn = postForm(url, data);
        int response = conn.getResponseCode();
        System.out.println("Response: " + response);
        StringBuilder sb = new StringBuilder();
        if (response == HttpsURLConnection.HTTP_OK) {
            try (InputStream in = conn.getInputStream()) {
                Scanner s = new Scanner(in);
                while (s.hasNextLine()) {
                    sb.append(s.nextLine());
                    sb.append("\n");
                }
            }
            return sb.toString();
        } else {
            try (InputStream err = conn.getErrorStream()) {
                Scanner s = new Scanner(err);
                while (s.hasNextLine()) {
                    sb.append(s.nextLine());
                    sb.append("\n");
                }
            }
            System.err.println("Error: " + sb.toString());
        }
        return null;
    }

    public static Reference postForReference(URL url, byte[] data) throws IOException {
        HttpsURLConnection conn = postForm(url, data);
        int response = conn.getResponseCode();
        System.out.println("Response: " + response);
        if (response == HttpsURLConnection.HTTP_OK) {
            try (InputStream in = conn.getInputStream()) {
                return Reference.parseDelimitedFrom(in);
            }
        } else {
            StringBuilder sb = new StringBuilder();
            try (InputStream err = conn.getErrorStream()) {
                Scanner s = new Scanner(err);
                while (s.hasNextLine()) {
                    sb.append(s.nextLine());
                    sb.append("\n");
                }
            }
            System.err.println("Error: " + sb.toString());
        }
        return null;
    }

    public static HttpsURLConnection postForm(URL url, byte[] data) throws IOException {
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
        try (OutputStream out = conn.getOutputStream()) {
            out.write(data);
            out.flush();
        }
        return conn;
    }

}
