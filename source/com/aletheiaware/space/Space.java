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

package com.aletheiaware.space;

import com.aletheiaware.bc.utils.BCUtils;
import com.aletheiaware.common.utils.CommonUtils.Pair;
import com.aletheiaware.crypto.Crypto;

import java.io.Console;
import java.io.File;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.util.Arrays;
import java.util.List;

public class Space {

    public static void main(String[] args) {
        for (Provider provider: Security.getProviders()) {
            for (String key: provider.stringPropertyNames()) {
                System.out.println(provider.getName() + ":" + key + ":" + provider.getProperty(key));
            }
        }
        try {
            File home = new File(System.getProperty("user.home"));
            File keystore = new File(home, "bc");
            Pair<String, KeyPair> identity = getIdentityFromConsole(keystore);
            System.out.println(identity.a);
            System.out.println(identity.b);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static Pair<String, KeyPair> getIdentityFromConsole(File keystore) throws Exception {
        String alias = null;
        KeyPair keys = null;
        Console console = System.console();
        if (console != null) {
            try {
                List<String> ks = Crypto.listRSAKeyPairs(keystore);
                if (ks.isEmpty()) {
                    console.printf("Creating new keystore %s\n", keystore.getAbsolutePath());
                } else {
                    console.printf("Found keys in %s\n", keystore.getAbsolutePath());
                    for (String k : ks) {
                        console.printf("Key:%s\n", k);
                    }
                }
                alias = console.readLine("Enter alias:\n");
                if (ks.contains(alias)) {
                    char[] password = console.readPassword("Enter password:\n");
                    keys = Crypto.getRSAKeyPair(keystore, alias, password);
                } else {
                    console.printf("New Key: %s\n", alias);
                    char[] password = console.readPassword("Enter password:\n");
                    char[] confirm = console.readPassword("Confirm password:\n");
                    if (confirm.length != password.length) {
                        System.err.println("Passwords differ in length");
                        return null;
                    } else if (!Arrays.equals(confirm, password)) {
                        System.err.println("Passwords do not match");
                        return null;
                    }
                    keys = Crypto.createRSAKeyPair(keystore, alias, password);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else {
            System.out.println("Console is null");
            return null;
        }
        return new Pair(alias, keys);
    }
}