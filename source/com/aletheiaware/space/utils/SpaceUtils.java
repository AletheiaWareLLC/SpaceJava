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

import com.aletheiaware.bc.BC;
import com.aletheiaware.bc.BCProto.Block;
import com.aletheiaware.bc.BCProto.BlockEntry;
import com.aletheiaware.bc.BCProto.CompressionAlgorithm;
import com.aletheiaware.bc.BCProto.EncryptionAlgorithm;
import com.aletheiaware.bc.BCProto.Record;
import com.aletheiaware.bc.BCProto.Record.Access;
import com.aletheiaware.bc.BCProto.Reference;
import com.aletheiaware.bc.BCProto.SignatureAlgorithm;
import com.aletheiaware.bc.Cache;
import com.aletheiaware.bc.Channel;
import com.aletheiaware.bc.Channel.RecordCallback;
import com.aletheiaware.bc.Crypto;
import com.aletheiaware.bc.Network;
import com.aletheiaware.bc.PoWChannel;
import com.aletheiaware.bc.utils.ChannelUtils;
import com.aletheiaware.common.utils.CommonUtils;
import com.aletheiaware.finance.FinanceProto.Subscription;
import com.aletheiaware.space.SpaceProto.Meta;
import com.aletheiaware.space.SpaceProto.Miner;
import com.aletheiaware.space.SpaceProto.Registrar;
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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;

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

    // Application-{Tool,Feature}-Hash
    public static final String SPACE_PREFIX_FILE = "Space-File-";
    public static final String SPACE_PREFIX_META = "Space-Meta-";
    public static final String SPACE_PREFIX_PREVIEW = "Space-Preview-";
    public static final String SPACE_PREFIX_SHARE = "Space-Share-";
    public static final String SPACE_PREFIX_TAG = "Space-Tag-";

    // TODO public static final String SPACE_CHARGE = "Space-Charge";
    public static final String SPACE_MINER = "Space-Miner";
    public static final String SPACE_REGISTRAR = "Space-Registrar";
    // TODO public static final String SPACE_REGISTRATION = "Space-Registration";
    // TODO public static final String SPACE_SUBSCRIPTION = "Space-Subscription";
    // TODO public static final String SPACE_USAGE = "Space-Usage";

    public static final String UNKNOWN_TYPE = "?/?";
    public static final String IMAGE_JPEG_TYPE = "image/jpeg";
    public static final String IMAGE_PNG_TYPE = "image/png";
    public static final String IMAGE_WEBP_TYPE = "image/webp";
    public static final String TEXT_PLAIN_TYPE = "text/plain";
    public static final String PROTOBUF_TYPE = "application/x-protobuf";
    public static final String VIDEO_MPEG_TYPE = "video/mpeg";
    public static final String AUDIO_MPEG_TYPE = "audio/mpeg";

    public static final String DEFAULT_IMAGE_TYPE = "image/jpeg";
    public static final String DEFAULT_VIDEO_TYPE = "video/mpeg";
    public static final String DEFAULT_AUDIO_TYPE = "audio/mpeg";

    public static final int PREVIEW_IMAGE_SIZE = 128;
    public static final int PREVIEW_TEXT_LENGTH = 64;

    public static final int SOCKET_TIMEOUT = 2 * 60 * 1000;// 2 minutes

    private SpaceUtils() {}

    public static String getSpaceHostname(boolean debug) {
        return debug ? SPACE_HOST_TEST : SPACE_HOST;
    }

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
        } else if (ext.endsWith(".mp3")) {
            type = AUDIO_MPEG_TYPE;
        } else {
            type = UNKNOWN_TYPE;
            System.err.println("Unrecognized extention: " + ext);
        }
        return type;
    }

    public static boolean isAudio(String type) {
        return type.startsWith("audio/");
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

    public static Map<String, Miner> getMiners(Cache cache, Network network) throws IOException {
        final PoWChannel miners = new PoWChannel(SPACE_MINER, BC.THRESHOLD_STANDARD);
        try {
            ChannelUtils.pull(miners, cache, network);
        } catch (NoSuchAlgorithmException e) {
            /* Ignored */
            e.printStackTrace();
        }
        Map<String, Miner> ms = new HashMap<>();
        ChannelUtils.read(miners.getName(), miners.getHead(), null, cache, network, null, null, null, new RecordCallback() {
            @Override
            public boolean onRecord(ByteString blockHash, Block block, BlockEntry blockEntry, byte[] key, byte[] payload) {
                try {
                    Miner m = Miner.newBuilder().mergeFrom(payload).build();
                    String a = m.getMerchant().getAlias();
                    if (!ms.containsKey(a)) {
                        ms.put(a, m);
                    }
                } catch (InvalidProtocolBufferException e) {
                    e.printStackTrace();
                }
                return true;
            }
        });
        return ms;
    }

    public static Map<String, Registrar> getRegistrars(Cache cache, Network network) throws IOException {
        final PoWChannel registrars = new PoWChannel(SPACE_REGISTRAR, BC.THRESHOLD_STANDARD);
        try {
            ChannelUtils.pull(registrars, cache, network);
        } catch (NoSuchAlgorithmException e) {
            /* Ignored */
            e.printStackTrace();
        }
        Map<String, Registrar> rs = new HashMap<>();
        ChannelUtils.read(registrars.getName(), registrars.getHead(), null, cache, network, null, null, null, new RecordCallback() {
            @Override
            public boolean onRecord(ByteString blockHash, Block block, BlockEntry blockEntry, byte[] key, byte[] payload) {
                try {
                    Registrar r = Registrar.newBuilder().mergeFrom(payload).build();
                    String a = r.getMerchant().getAlias();
                    if (!rs.containsKey(a)) {
                        rs.put(a, r);
                    }
                } catch (InvalidProtocolBufferException e) {
                    e.printStackTrace();
                }
                return true;
            }
        });
        return rs;
    }

    public static void readMetas(Cache cache, Network network, String alias, KeyPair keys, ByteString metaRecordHash, RecordCallback callback) throws IOException {
        final PoWChannel metas = new PoWChannel(SPACE_PREFIX_META + alias, BC.THRESHOLD_STANDARD);
        try {
            ChannelUtils.pull(metas, cache, network);
        } catch (NoSuchAlgorithmException e) {
            /* Ignored */
            e.printStackTrace();
        }
        ChannelUtils.read(metas.getName(), metas.getHead(), null, cache, network, alias, keys, metaRecordHash, callback);
    }

    public static void readFiles(Cache cache, Network network, String alias, KeyPair keys, ByteString fileRecordHash, RecordCallback callback) throws IOException {
        final PoWChannel files = new PoWChannel(SPACE_PREFIX_FILE + alias, BC.THRESHOLD_STANDARD);
        ChannelUtils.loadHead(files, cache, network);
        ChannelUtils.read(files.getName(), files.getHead(), null, cache, network, alias, keys, fileRecordHash, callback);
    }

    public static void readPreviews(Cache cache, Network network, String alias, KeyPair keys, ByteString previewRecordHash, ByteString metaRecordHash, RecordCallback previewCallback) throws IOException {
        final PoWChannel previews = new PoWChannel(SPACE_PREFIX_PREVIEW + new String(CommonUtils.encodeBase64URL(metaRecordHash.toByteArray())), BC.THRESHOLD_STANDARD);
        try {
            ChannelUtils.pull(previews, cache, network);
        } catch (NoSuchAlgorithmException e) {
            /* Ignored */
            e.printStackTrace();
        }
        ChannelUtils.read(previews.getName(), previews.getHead(), null, cache, network, alias, keys, previewRecordHash, previewCallback);
    }

    public static void readShares(Cache cache, Network network, String alias, KeyPair keys, ByteString shareRecordHash, ByteString metaRecordHash, RecordCallback shareCallback, RecordCallback metaCallback, RecordCallback fileCallback) throws IOException {
        final PoWChannel shares = new PoWChannel(SPACE_PREFIX_SHARE + alias, BC.THRESHOLD_STANDARD);
        try {
            ChannelUtils.pull(shares, cache, network);
        } catch (NoSuchAlgorithmException e) {
            /* Ignored */
            e.printStackTrace();
        }
        ChannelUtils.read(shares.getName(), shares.getHead(), null, cache, network, alias, keys, shareRecordHash, new RecordCallback() {
            @Override
            public boolean onRecord(ByteString blockHash, Block block, BlockEntry blockEntry, byte[] key, byte[] payload) {
                try {
                    if (shareCallback != null) {
                        shareCallback.onRecord(blockHash, block, blockEntry, key, payload);
                    }
                    Share share = Share.newBuilder().mergeFrom(payload).build();
                    Reference sharedMetaReference = share.getMetaReference();
                    if (metaRecordHash == null || sharedMetaReference.getRecordHash().equals(metaRecordHash)) {
                        Block sharedMetaBlock = ChannelUtils.getBlockContainingRecord(sharedMetaReference.getChannelName(), cache, network, sharedMetaReference.getRecordHash());
                        if (sharedMetaBlock != null) {
                            for (BlockEntry sharedMetaBlockEntry : sharedMetaBlock.getEntryList()) {
                                if (sharedMetaReference.getRecordHash().equals(sharedMetaBlockEntry.getRecordHash())) {
                                    Record sharedMetaRecord = sharedMetaBlockEntry.getRecord();
                                    if (metaCallback != null) {
                                        try {
                                            byte[] metaKey = share.getMetaKey().toByteArray();
                                            byte[] decryptedPayload = Crypto.decryptAES(metaKey, sharedMetaRecord.getPayload().toByteArray());
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
                                            Block chunkBlock = ChannelUtils.getBlockContainingRecord(chunkReference.getChannelName(), cache, network, chunkReference.getRecordHash());
                                            if (chunkBlock != null) {
                                                for (BlockEntry chunkEntry : chunkBlock.getEntryList()) {
                                                    if (chunkReference.getRecordHash().equals(chunkEntry.getRecordHash())) {
                                                        Record chunkRecord = chunkEntry.getRecord();
                                                        try {
                                                            byte[] chunkKey = chunkKeys.get(i).toByteArray();
                                                            byte[] decryptedPayload = Crypto.decryptAES(chunkKey, chunkRecord.getPayload().toByteArray());
                                                            fileCallback.onRecord(chunkReference.getBlockHash(), chunkBlock, chunkEntry, chunkKey, decryptedPayload);
                                                        } catch (BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException ex) {
                                                            /* Ignored */
                                                            ex.printStackTrace();
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                } catch (InvalidProtocolBufferException | NoSuchAlgorithmException e) {
                    e.printStackTrace();
                }
                return true;
            }
        });
    }

    public static Reference postRecord(String host, String feature, Record record) throws IOException {
        URL url = new URL(host + "/mining/" + feature);
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

}
