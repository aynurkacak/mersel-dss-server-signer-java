package io.mersel.dss.signer.api.services.keystore;

import io.mersel.dss.signer.api.exceptions.KeyStoreException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.AuthProvider;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.util.StringJoiner;

/**
 * PKCS#11 donanım güvenlik modülleri (HSM) için KeyStore sağlayıcısı.
 * Java 11+ uyumlu hale getirilmiştir.
 */
public class PKCS11KeyStoreProvider implements KeyStoreProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(PKCS11KeyStoreProvider.class);

    private final String libraryPath;
    private final Long slotIndex;
    private final String providerName;
    private final Long slot;

    public PKCS11KeyStoreProvider(String libraryPath, Long slot, Long slotIndex) {
        this.libraryPath = libraryPath;
        this.slot = slot;
        this.slotIndex = slotIndex;
        this.providerName = "PKCS11Provider_" + System.identityHashCode(this);
    }

    @Override
    public KeyStore loadKeyStore(char[] pin) {
        try {
            Provider provider = buildPKCS11Provider();
            KeyStore keyStore = KeyStore.getInstance("PKCS11", provider);
            keyStore.load(null, pin);
            
            LOGGER.info("PKCS11 KeyStore başarıyla yüklendi. Kütüphane: {}", libraryPath);
            return keyStore;
            
        } catch (Exception e) {
            throw new KeyStoreException("PKCS11 keystore yüklenemedi: " + libraryPath, e);
        }
    }

    @Override
    public String getType() {
        return "PKCS11";
    }

    private Provider buildPKCS11Provider() {
        ensureBouncyCastleRegistered();

        // Java 11+ için konfigürasyon string formatında hazırlanır
        StringJoiner configJoiner = new StringJoiner(System.lineSeparator());
        configJoiner.add("name = " + providerName);
        configJoiner.add("library = " + "\"" + libraryPath.replace("\\", "\\\\") + "\"");

        if (slotIndex != null && slotIndex >= 0) {
            configJoiner.add("slotListIndex = " + slotIndex);
        } else if (slot != null && slot >= 0) {
            configJoiner.add("slot = " + slot);
        }

        // Java 9+ için SunPKCS11 yükleme yöntemi
        Provider p = Security.getProvider("SunPKCS11");
        p = ((AuthProvider) p).configure("--" + configJoiner.toString());
        Security.addProvider(p);
        
        LOGGER.debug("PKCS11 provider yapılandırıldı: {}", providerName);
        return p;
    }

    private static synchronized void ensureBouncyCastleRegistered() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) != null) {
            return;
        }

        Security.removeProvider("SunEC");
        Security.insertProviderAt(new BouncyCastleProvider(), 1);

        LOGGER.info("BouncyCastle provider pozisyon 1'e kayıt edildi, SunEC kaldırıldı " +
                    "(EC explicit parameters desteği için)");
    }
}