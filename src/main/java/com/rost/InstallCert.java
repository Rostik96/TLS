package com.rost;
/*
 * Copyright 2006 Sun Microsystems, Inc.  All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   - Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   - Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *   - Neither the name of Sun Microsystems nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.collections4.IteratorUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.validator.routines.UrlValidator;

import javax.net.ssl.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class InstallCert {
    private static final BufferedReader console = new BufferedReader(new InputStreamReader(System.in));
    private static String host;
    private static int port;
    private static String passphrase;
    private static Path keyStorePath;

    public static void main(String[] args) throws Exception {
//        host = readHost();
//        port = readPort();
//        Path jdkSecurityFolder = readPath();
//        passphrase = readPassword();

        host = "artifactory.vsk.ru";
        port = 443;
        passphrase = readPassword();
        Path jdkSecurityFolder = Path.of("/home/rostislav/.jdks/openjdk-17.0.1/lib/security");
        keyStorePath = jdkSecurityFolder.resolve("cacerts");

        System.out.println(host);
        System.out.println(port);
        System.out.print(passphrase);
        System.out.println(keyStorePath);

        System.out.println("Loading KeyStore " + keyStorePath + "...");

        KeyStore keyStore;
        try (InputStream in = Files.newInputStream(keyStorePath)) {
            keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(in, passphrase.toCharArray());
        }
        keyStore.aliases().asIterator().forEachRemaining(System.out::println);
        printInfo(keyStore);
        TrustManagerFactory trustManager = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManager.init(keyStore);

        X509TrustManager defaultTrustManager = (X509TrustManager) trustManager.getTrustManagers()[0];
        SavingTrustManager tm = new SavingTrustManager(defaultTrustManager);

        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, new TrustManager[]{tm}, null);
        SSLSocketFactory factory = context.getSocketFactory();

        System.out.println("Opening connection to " + host + ":" + port + "...");
        SSLSocket socket = (SSLSocket) factory.createSocket(host, port);
        socket.setSoTimeout(10000);
        try {
            System.out.println("Starting SSL handshake...");
            socket.startHandshake();
            socket.close();
            System.out.println();
            System.out.println("No errors, certificate is already trusted");
        } catch (SSLException e) {
            System.out.println();
            e.printStackTrace(System.out);
        }

        X509Certificate[] chain = tm.chain;
        if (chain == null) {
            System.out.println("Could not obtain server certificate chain");
            return;
        }

        System.out.printf("\nServer sent %d certificate(s):\n\n", chain.length);
        MessageDigest sha1 = MessageDigest.getInstance("SHA1");
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        for (int i = 0; i < chain.length; i++) {
            X509Certificate cert = chain[i];

            System.out.println("-----BEGIN CERTIFICATE-----");
            final Base64.Encoder encoder = Base64.getMimeEncoder(64, System.lineSeparator().getBytes());
            System.out.println(new String(encoder.encode(cert.getEncoded())));
            System.out.println("-----END CERTIFICATE-----");

            System.out.println(" " + (i + 1) + " Subject " + cert.getSubjectDN());
            System.out.println("   Issuer  " + cert.getIssuerDN());
            sha1.update(cert.getEncoded());
            System.out.println("   sha1    " + Hex.encodeHexString(sha1.digest()));
            md5.update(cert.getEncoded());
            System.out.println("   md5     " + Hex.encodeHexString(md5.digest()) + '\n');
        }

        System.out.println("Enter certificate number to add to trusted keystore or 'q' to quit: [1]");
        String line = console.readLine().trim();
        int k;
        try {
            k = (line.length() == 0) ? 0 : Integer.parseInt(line) - 1;
        } catch (NumberFormatException e) {
            System.out.println("KeyStore not changed");
            return;
        }

        X509Certificate cert = chain[k];
        String alias = "artifactory";//host + "-" + (k + 1);
        keyStore.setCertificateEntry(alias, cert);

        try (OutputStream out = Files.newOutputStream(keyStorePath)) {
            keyStore.store(out, passphrase.toCharArray());
        }

        System.out.printf("\n%s\n\n", cert);
        System.out.println("Added certificate to keystore 'cacerts' using alias '" + alias + "'");
        printInfo(keyStore);
    }

    private static void printInfo(KeyStore keyStore) throws KeyStoreException {
        System.out.println("Keystore contains \"cavsk\": " + IteratorUtils.toList(keyStore.aliases().asIterator()).contains("vsk"));
    }

    private static void checkParams(String... args) {
        if (args.length != 1 && args.length != 2) {
            System.out.println("Usage: java InstallCert <host>[:port] [passphrase]");
            System.exit(-1);
        }
    }

    private static String readHost() throws IOException {
        String host;
        UrlValidator validator = new UrlValidator();
        do {
            System.out.print("Inter the host: ");
            host = console.readLine();
        } while (!validator.isValid(host));
        System.out.printf("host is \"%s\"\n", host);
        return StringUtils.substringAfter(host, "//");
    }

    private static int readPort() throws IOException {
        String host;
        do {
            System.out.print("Enter the port: ");
            host = console.readLine();
            if (host.isEmpty())
                host = "443";
            break;
        } while (!host.matches("\\d+"));

        System.out.printf("port is \"%s\"\n", host);
        return Integer.parseInt(host);
    }

    private static Path readPath() throws IOException {
        Path securityPath;
        do {
            System.out.print("Inter the absolute path to JDK \"security\" folder: ");
            securityPath = Path.of(console.readLine());
        } while (!securityPath.isAbsolute() && !Files.isDirectory(securityPath));
        System.out.printf("security's path is \"%s\"\n", securityPath);
        return securityPath;
    }

    private static String readPassword() throws IOException {
        String password;
        System.out.print("Enter the keystore password: ");
        password = console.readLine();
        System.out.printf("password is \"%s\"\n", password);
        return password;
    }

    private static class SavingTrustManager implements X509TrustManager {

        private final X509TrustManager tm;
        private X509Certificate[] chain;

        SavingTrustManager(X509TrustManager tm) {
            this.tm = tm;
        }

        public X509Certificate[] getAcceptedIssuers() {
            throw new UnsupportedOperationException();
        }

        public void checkClientTrusted(X509Certificate[] chain, String authType) {
            throw new UnsupportedOperationException();
        }

        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            this.chain = chain;
            tm.checkServerTrusted(chain, authType);
        }
    }

}
