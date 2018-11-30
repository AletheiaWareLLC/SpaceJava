/*
 * Copyright 2018 Aletheia Ware LLC
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

import com.aletheiaware.bc.BC.Block;
import com.aletheiaware.bc.BC.BlockEntry;
import com.aletheiaware.bc.BC.Message;
import com.aletheiaware.bc.BC.Message.Access;
import com.aletheiaware.bc.BC.Reference;
import com.aletheiaware.bc.utils.BCUtils;
import com.aletheiaware.space.Space.Meta;
import com.aletheiaware.space.Space.Registration;
import com.aletheiaware.space.Space.StorageRequest;
import com.aletheiaware.space.Space.StorageRequest.Bundle;
import com.aletheiaware.space.Space.StorageResponse;
import com.google.protobuf.ByteString;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
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
import java.text.DateFormat;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public final class SpaceUtils {

    public static final String TAG = "Space";

    public static final String FILE_CHANNEL_PREFIX = "Space File ";
    public static final String META_CHANNEL_PREFIX = "Space Meta ";
    public static final String PREVIEW_CHANNEL_PREFIX = "Space Preview ";
    public static final String REGISTRATION_CHANNEL = "Space Registration";

    public static final String IMAGE_JPEG_TYPE = "image/jpeg";
    public static final String IMAGE_PNG_TYPE = "image/png";
    public static final String IMAGE_WEBP_TYPE = "image/webp";
    public static final String TEXT_PLAIN_TYPE = "text/plain";
    public static final String PROTOBUF_TYPE = "application/x-protobuf";
    public static final String UNKNOWN_TYPE = "";

    public static final int PREVIEW_IMAGE_SIZE = 128;
    public static final int PREVIEW_TEXT_LENGTH = 128;

    public static final int SOCKET_TIMEOUT = 2 * 60 * 1000;// 2 minutes

    private static final DateFormat FORMATTER = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT);

    public static String sizeToString(long size) {
        if (size <= 1024) {
            return String.format("%d bytes", size);
        }
        String unit = "";
        double s = size;
        if (s >= 1024) {
            s /= 1024;
            unit = "Kb";
        }
        if (s >= 1024) {
            s /= 1024;
            unit = "Mb";
        }
        if (s >= 1024) {
            s /= 1024;
            unit = "Gb";
        }
        if (s >= 1024) {
            s /= 1024;
            unit = "Tb";
        }
        if (s >= 1024) {
            s /= 1024;
            unit = "Pb";
        }
        return String.format("%.2f %s", s, unit);
    }

    public static String timeToString(long timestamp) {
        return FORMATTER.format(new Date(timestamp));
    }

    public static String getFileType(File file) throws IOException {
        String type = null;
        try {
            type = Files.probeContentType(file.toPath());
        } catch (Exception e) {
            /* Ignored */
        }
        if (type == null) {
            String filename = file.getName();
            if (filename.endsWith(".jpg") || filename.endsWith(".jpeg")) {
                type = IMAGE_JPEG_TYPE;
            } else if (filename.endsWith(".png")) {
                type = IMAGE_PNG_TYPE;
            } else if (filename.endsWith(".webp")) {
                type = IMAGE_WEBP_TYPE;
            } else if (filename.endsWith(".txt")) {
                type = TEXT_PLAIN_TYPE;
            } else if (filename.endsWith(".pb")) {
                type = PROTOBUF_TYPE;
            } else {
                System.err.println("Unrecognized file type: " + filename);
                type = UNKNOWN_TYPE;
            }
        }
        return type;
    }

    public static boolean isImage(String type) {
        return type.startsWith("image/");
    }

    public static boolean isText(String type) {
        return type.startsWith("text/");
    }

    /**
     * Sorts a list of Message hashes by the timestamp of the Meta they map to.
     */
    public static void sort(List<ByteString> hashes, Map<ByteString, Long> timestamps) {
        Collections.sort(hashes, new Comparator<ByteString>() {
            @Override
            public int compare(ByteString b1, ByteString b2) {
                return Long.compare(timestamps.get(b1), timestamps.get(b2));
            }
        });
    }

    public static Bundle createBundle(KeyPair keyPair, byte[] data) throws BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, SignatureException {
        byte[] key = BCUtils.generateSecretKey(BCUtils.AES_KEY_SIZE_BYTES);
        byte[] payload = BCUtils.encryptAES(key, data);
        byte[] signature = BCUtils.sign(keyPair.getPrivate(), payload);
        return Bundle.newBuilder()
                .setKey(ByteString.copyFrom(BCUtils.encryptRSA(keyPair.getPublic(), key)))
                .setPayload(ByteString.copyFrom(payload))
                .setSignature(ByteString.copyFrom(signature))
                .build();
    }

    public static StorageRequest createRequest(KeyPair keys, String customerId, String paymentId, String name, String type, byte[] data, byte[] preview) throws BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, SignatureException {
        StorageRequest.Builder rb = StorageRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(keys.getPublic().getEncoded()))
                .setFile(createBundle(keys, data))
                .setMeta(createBundle(keys, Meta.newBuilder()
                        .setName(name)
                        .setType(type)
                        .setSize(data.length)
                        .build()
                        .toByteArray()));
        if (customerId != null) {
            rb.setCustomerId(customerId);
        } else {
            rb.setPaymentId(paymentId);
        }
        if (preview != null) {
            rb.setPreview(createBundle(keys, preview));
        }
        return rb.build();
    }

    public static String getCustomerId(InetAddress address, KeyPair keys) throws IOException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, BadPaddingException {
        Reference head = getHead(address, Reference.newBuilder()
                .setChannelName(REGISTRATION_CHANNEL)
                .build());
        if (head != null) {
            ByteString publicKeyHash = ByteString.copyFrom(BCUtils.getHash(keys.getPublic().getEncoded()));
            ByteString bh = head.getBlockHash();
            while (bh != null && !bh.isEmpty()) {
                Block b = getBlock(address, Reference.newBuilder()
                        .setBlockHash(bh)
                        .setChannelName(REGISTRATION_CHANNEL)
                        .build());
                for (BlockEntry e : b.getEntryList()) {
                    Message m = e.getMessage();
                    for (Message.Access a : m.getRecipientList()) {
                        if (a.getPublicKeyHash().equals(publicKeyHash)) {
                            byte[] key = a.getSecretKey().toByteArray();
                            byte[] decryptedKey = BCUtils.decryptRSA(keys.getPrivate(), key);
                            byte[] decryptedPayload = BCUtils.decryptAES(decryptedKey, m.getPayload().toByteArray());
                            return Registration.parseFrom(decryptedPayload).getCustomerId();
                        }
                    }
                }
                bh = b.getPrevious();
            }
        }
        return null;
    }

    public static Reference getHead(InetAddress address, Reference reference) throws IOException {
        int port = BCUtils.PORT_HEAD;
        Socket s = new Socket(address, port);
        InputStream in = s.getInputStream();
        OutputStream out = s.getOutputStream();
        reference.writeDelimitedTo(out);
        out.flush();
        return Reference.parseDelimitedFrom(in);
    }

    public static Block getBlock(InetAddress address, Reference reference) throws IOException {
        int port = BCUtils.PORT_BLOCK;
        Socket s = new Socket(address, port);
        InputStream in = s.getInputStream();
        OutputStream out = s.getOutputStream();
        reference.writeDelimitedTo(out);
        out.flush();
        return Block.parseDelimitedFrom(in);
    }

    public static byte[] getMessageData(InetAddress address, KeyPair keys, Reference reference) throws BadPaddingException, IOException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, SignatureException {
        Block block = getBlock(address, reference);
        if (block != null) {
            ByteString messageHash = reference.getMessageHash();
            ByteString keyHash = ByteString.copyFrom(BCUtils.getHash(keys.getPublic().getEncoded()));
            for (BlockEntry e : block.getEntryList()) {
                if (e.getMessageHash().equals(messageHash)) {
                    Message m = e.getMessage();
                    for (Access a : m.getRecipientList()) {
                        if (a.getPublicKeyHash().equals(keyHash)) {
                            // TODO check signature
                            // Decrypt secret key
                            byte[] key = BCUtils.decryptRSA(keys.getPrivate(), a.getSecretKey().toByteArray());
                            // Decrypt payload
                            // TODO get cipher type from message
                            byte[] payload = BCUtils.decryptAES(key, m.getPayload().toByteArray());
                            return payload;
                        }
                    }
                    System.err.println("No access for given keypair");
                    return null;
                }
            }
            System.err.println("No message found for given hash");
            return null;
        }
        System.err.println("No block found for given reference");
        return null;
    }

    public static StorageResponse sendRequest(InetAddress address, StorageRequest request) throws IOException {
        int port = BCUtils.PORT_WRITE;
        Socket s = new Socket(address, port);
        InputStream in = s.getInputStream();
        OutputStream out = s.getOutputStream();
        request.writeDelimitedTo(out);
        out.flush();
        return StorageResponse.parseDelimitedFrom(in);
    }

}
