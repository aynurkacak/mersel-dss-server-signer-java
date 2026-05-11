package io.mersel.dss.signer.api.services.signature.xades;

import java.io.InputStream;
import java.util.Base64;
import java.util.concurrent.Semaphore;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.signature.XAdESLevelC;
import eu.europa.esig.dss.xades.signature.XAdESService;
import eu.europa.esig.dss.xades.signature.XAdESSignatureBuilder;
import io.mersel.dss.signer.api.exceptions.SignatureException;
import io.mersel.dss.signer.api.models.SignResponse;
import io.mersel.dss.signer.api.models.SigningMaterial;
import io.mersel.dss.signer.api.models.enums.DocumentType;
import io.mersel.dss.signer.api.services.crypto.CryptoSignerService;
import java.nio.charset.StandardCharsets;
import eu.europa.esig.dss.xades.signature.XAdESCounterSignatureParameters; 
// Enum tanımı için gerekli (halihazırda olabilir ama kontrol et)
import eu.europa.esig.dss.enumerations.SignaturePackaging;

/**
 * XAdES imzaları oluşturan servis.
 * UBL, e-Arşiv Raporu, HrXml gibi çeşitli belge tiplerini destekler.
 *
 * <p>
 * Desteklenen belge türleri:
 * <ul>
 * <li>e-Fatura (UBL Invoice)</li>
 * <li>e-Arşiv Raporu (XAdES-A seviyesine otomatik yükseltilir)</li>
 * <li>e-İrsaliye (Waybill)</li>
 * <li>İrsaliye Yanıtı (Waybill Response)</li>
 * <li>Uygulama Yanıtı (Application Response)</li>
 * <li>HrXml (Kullanıcı Açma/Kapama)</li>
 * <li>Diğer XML belgeleri</li>
 * </ul>
 */
@Service
public class XAdESSignatureService {

    private static final Logger LOGGER = LoggerFactory.getLogger(XAdESSignatureService.class);
    private static final String DEFAULT_XML_NAME = "document.xml";
    private static final String ZIP_ENTRY_NAME = "signedcontent.xml";
    private static final String SIGNED_PROPERTIES_TYPE = "http://uri.etsi.org/01903#SignedProperties";

    private final XAdESService xadesService;
    private final XAdESParametersBuilderService parametersBuilder;
    private final XmlProcessingService xmlProcessor;
    private final XAdESDocumentPlacementService documentPlacement;
    private final XAdESLevelUpgradeService levelUpgradeService;
    private final CryptoSignerService cryptoSigner;
    private final CertificateVerifier certificateVerifier;
    private final io.mersel.dss.signer.api.services.util.CompressionService compressionService;
    private final Semaphore semaphore;

    public XAdESSignatureService(XAdESService xadesService,
            XAdESParametersBuilderService parametersBuilder,
            XmlProcessingService xmlProcessor,
            XAdESDocumentPlacementService documentPlacement,
            XAdESLevelUpgradeService levelUpgradeService,
            CryptoSignerService cryptoSigner,
            CertificateVerifier certificateVerifier,
            io.mersel.dss.signer.api.services.util.CompressionService compressionService,
            Semaphore signatureSemaphore) {
        this.xadesService = xadesService;
        this.parametersBuilder = parametersBuilder;
        this.xmlProcessor = xmlProcessor;
        this.documentPlacement = documentPlacement;
        this.levelUpgradeService = levelUpgradeService;
        this.cryptoSigner = cryptoSigner;
        this.certificateVerifier = certificateVerifier;
        this.compressionService = compressionService;
        this.semaphore = signatureSemaphore;
    }

    /**
     * XML belgesini XAdES imzası ile imzalar.
     *
     * @param xmlInputStream XML belgesi içeren input stream
     * @param documentType   Belge tipi (e-Fatura, e-Arşiv vb.)
     * @param signatureId    İsteğe bağlı imza tanımlayıcısı
     * @param zipped         Belgenin ZIP formatında olup olmadığı
     * @param material       İmzalama sertifikası ve private key içeren materyal
     * @return İmzalanmış belge ve imza değeri içeren yanıt
     */
    public SignResponse signXml(InputStream xmlInputStream,
            DocumentType documentType,
            String signatureId,
            boolean zipped,
            SigningMaterial material) {
        try {
            // 1. XML byte'larını çıkar
            byte[] xmlBytes = extractXmlBytes(xmlInputStream, zipped);

            // 2. Belge tipini normalize et
            if (documentType == null || documentType == DocumentType.None) {
                documentType = DocumentType.OtherXmlDocument;
            }

            // 3. Belgeyi parse et
            Document document = xmlProcessor.parseDocument(xmlBytes);

            // 4. UBL belgeleri için UBLExtensions'ı imzadan ÖNCE ekle.
            // İmza, belgenin canonical formu üzerinden hesaplanır. UBLExtensions
            // imza yerleştirme sırasında eklenirse, imzalanan içerik ile nihai
            // belge uyuşmaz ve doğrulama başarısız olur.
            if (documentType == DocumentType.UblDocument) {
                documentPlacement.ensureUblExtensionContentExists(document);
                xmlBytes = xmlProcessor.documentToBytes(document);
            }

            // 5. Parametreleri oluştur
            DSSDocument dssDocument = new InMemoryDocument(xmlBytes, DEFAULT_XML_NAME,
                    MimeType.fromFileExtension("xml"));
            XAdESSignatureParameters parameters = parametersBuilder.buildParameters(
                    document, documentType, signatureId, material);

            // 6. İmzalama sertifika zincirini doğrulayıcıya ekle
            addSigningCertificateChainToVerifier(material);

            // 7. İmzayı oluştur
            SignResponse response = createSignature(document, dssDocument, parameters,
                    documentType, material);

            // 8. Gerekirse ZIP'le
            if (zipped) {
                byte[] zippedBytes = compressionService.zipBytes(ZIP_ENTRY_NAME, response.getSignedDocument());
                return new SignResponse(zippedBytes, response.getSignatureValue());
            }

            LOGGER.info("XAdES imzası başarıyla oluşturuldu. Belge tipi: {}", documentType);

            return response;

        } catch (SignatureException e) {
            throw e;
        } catch (Exception e) {
            LOGGER.error("XAdES imzası oluşturulurken hata", e);
            throw new SignatureException("XAdES imzası oluşturulamadı", e);
        }
    }

    /**
     * İmzalama sürecini orkestre ederek imzayı oluşturur.
     * Semaphore ile eşzamanlı imza sayısını kontrol eder.
     */
    private SignResponse createSignature(Document mainDocument,
            DSSDocument dssDocument,
            XAdESSignatureParameters parameters,
            DocumentType documentType,
            SigningMaterial material) throws Exception {

        // OCSP cache cleanup için signature ID'yi takip et
        String actualSignatureId = null;
        SignatureValue capturedSignatureValue = null;

        semaphore.acquire();
        try {
            // Referanslar için içerik ayarla
            if (parameters.getReferences() != null) {
                for (DSSReference reference : parameters.getReferences()) {
                    if (reference.getContents() == null &&
                            (reference.getType() == null ||
                                    !SIGNED_PROPERTIES_TYPE.equals(reference.getType()))) {
                        reference.setContents(dssDocument);
                    }
                }
            }



            String targetSignatureId = null;
            org.w3c.dom.NodeList sigs = mainDocument.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature");
            if (sigs.getLength() > 0) {
                targetSignatureId = ((org.w3c.dom.Element)sigs.item(0)).getAttribute("Id");
            }
            DSSDocument signedDocument;
            if (targetSignatureId != null && !targetSignatureId.isEmpty()) {
                LOGGER.info("Counter signature işlemi başlatılıyor. Hedef imza: {}", targetSignatureId);

                XAdESCounterSignatureParameters counterParams = new XAdESCounterSignatureParameters();
                counterParams.setSignatureIdToCounterSign(targetSignatureId);
                counterParams.setEn319132(false);
                counterParams.setSignatureLevel(parameters.getSignatureLevel());
                counterParams.setDigestAlgorithm(parameters.getDigestAlgorithm());
                counterParams.setSignaturePackaging(SignaturePackaging.DETACHED); 

                counterParams.setSigningCertificate(parameters.getSigningCertificate());
                counterParams.setCertificateChain(parameters.getCertificateChain());

                // 1. Karşı imzayı hesapla
                ToBeSigned dataToSign = xadesService.getDataToSign(dssDocument, counterParams);
                SignatureValue signatureValue = cryptoSigner.sign(dataToSign, material.getPrivateKey(), parameters.getDigestAlgorithm());
                
                // Counter-signature eklenmiş TÜM XML'i al
                DSSDocument counterSignedDoc = xadesService.counterSignSignature(dssDocument, counterParams, signatureValue);

                // 2. Mükerrerliği önlemek için kritik adım: 
                // Mevcut ana dökümandaki (mainDocument) eski imzayı BUL ve SİL
                org.w3c.dom.NodeList existingSigs = mainDocument.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature");
                for (int i = 0; i < existingSigs.getLength(); i++) {
                    org.w3c.dom.Node sigNode = existingSigs.item(i);
                    sigNode.getParentNode().removeChild(sigNode);
                }

                // 3. DSS'ten gelen dökümandan güncel imzayı (counter signature içeren halini) al
                byte[] counterSignedBytes = xmlProcessor.dssDocumentToBytes(counterSignedDoc);
                Document tempDom = xmlProcessor.parseDocument(counterSignedBytes);
                Element updatedSignatureElement = (Element) tempDom.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature").item(0);

                if (updatedSignatureElement != null) {
                    // CounterSignature elementlerini bul
                    org.w3c.dom.NodeList counterSigs = updatedSignatureElement.getElementsByTagNameNS("http://uri.etsi.org/01903/v1.3.2#", "CounterSignature");
                    
                    for (int i = 0; i < counterSigs.getLength(); i++) {
                        Element counterSigElement = (Element) counterSigs.item(i);
                        // "Id" özniteliği şema tarafından istenmediği için siliyoruz
                        if (counterSigElement.hasAttribute("Id")) {
                            counterSigElement.removeAttribute("Id");
                        }
                    }
                }

                // 4. Güncel imzayı boşaltılmış dökümana yerleştir
                if (updatedSignatureElement != null) {
                    documentPlacement.placeSignatureElement(mainDocument, updatedSignatureElement, documentType);
                }

                byte[] finalBytes = xmlProcessor.documentToBytes(mainDocument);
                String encodedSig = Base64.getEncoder().encodeToString(signatureValue.getValue());
                
                return new SignResponse(finalBytes, encodedSig);
            }
            // İmza oluşturucuyu hazırla
            XAdESSignatureBuilder signatureBuilder = XAdESSignatureBuilder.getSignatureBuilder(
                    parameters, dssDocument, certificateVerifier);
            parameters.getContext().setBuilder(signatureBuilder);

            ToBeSigned dataToSign = new ToBeSigned(signatureBuilder.build());

            // Veriyi imzala
            SignatureValue signatureValue = cryptoSigner.sign(
                    dataToSign,
                    material.getPrivateKey(),
                    parameters.getDigestAlgorithm());



            // SignatureValue'yu yakala (response için)
            capturedSignatureValue = signatureValue;

            // İmzalı belgeyi oluştur
            signedDocument = xadesService.signDocument(
                dssDocument, parameters, signatureValue);
            // e-Arşiv Raporu ise XAdES-A seviyesine yükselt
            signedDocument = levelUpgradeService.upgradeIfNeeded(
                    signedDocument, documentType, parameters);

            // Signature ID'yi yakala (cache cleanup için)
            SignedDocumentValidator tempValidator = SignedDocumentValidator.fromDocument(signedDocument);
            if (tempValidator.getSignatures() != null && !tempValidator.getSignatures().isEmpty()) {
                actualSignatureId = tempValidator.getSignatures().get(0).getId();
            }

            // Son işleme: İmzayı doğru konuma yerleştir
            byte[] signedBytes = xmlProcessor.dssDocumentToBytes(signedDocument);
            Document signedDom = xmlProcessor.parseDocument(signedBytes);
            Element signatureElement = xmlProcessor.findSignatureElement(signedDom);

            byte[] finalSignedBytes;
            if (signatureElement != null) {
                documentPlacement.placeSignatureElement(
                        mainDocument, signatureElement, documentType);
                finalSignedBytes = xmlProcessor.documentToBytes(mainDocument);
            } else {
                finalSignedBytes = signedBytes;
            }

            // SignatureValue'yu Base64 string'e çevir
            String encodedSignature = capturedSignatureValue != null
                    ? Base64.getEncoder().encodeToString(capturedSignatureValue.getValue())
                    : null;

            return new SignResponse(finalSignedBytes, encodedSignature);

        } finally {
            semaphore.release();

            // OCSP cache cleanup (memory leak önleme)
            if (actualSignatureId != null) {
                // 1. Bu imzaya özel cache'i temizle (her imza için)
                XAdESLevelC.cleanupOcspCache(actualSignatureId);

                // 2. Eski genel cache'leri temizle (sadece e-Arşiv Raporu/XAdES-A upgrade
                // yapıldıysa)
                // Çünkü XAdES-A upgrade sırasında çok fazla OCSP/CRL cache'i oluşur
                if (documentType == DocumentType.EArchiveReport || documentType == DocumentType.EBiletReport) {
                    XAdESLevelC.cleanupOldCaches(5 * 60 * 1000L);
                }
            }
        }
    }

    /**
     * İmzalama sertifika zincirini doğrulayıcının yardımcı kaynağına ekler.
     * Bu, DSS doğrulayıcısının zinciri çevrimiçi bulabilmesini sağlar.
     */
    private void addSigningCertificateChainToVerifier(SigningMaterial material) {
        if (!(certificateVerifier instanceof CommonCertificateVerifier)) {
            return;
        }

        CommonCertificateVerifier commonVerifier = (CommonCertificateVerifier) certificateVerifier;
        CertificateSource adjunctSource = commonVerifier.getAdjunctCertSources();

        CommonCertificateSource adjunct;
        if (adjunctSource instanceof CommonCertificateSource) {
            adjunct = (CommonCertificateSource) adjunctSource;
        } else {
            adjunct = new CommonCertificateSource();
            commonVerifier.setAdjunctCertSources(adjunct);
        }

        // İmzalama zincirindeki tüm sertifikaları ekle
        for (CertificateToken cert : material.getCertificateTokens()) {
            adjunct.addCertificate(cert);
        }

        LOGGER.debug("Doğrulayıcıya {} adet sertifika eklendi",
                material.getCertificateTokens().size());
    }

    /**
     * Input stream'den XML byte'larını çıkarır (ZIP içeriğini de işler).
     */
    private byte[] extractXmlBytes(InputStream inputStream, boolean zipped) {
        if (!zipped) {
            try {
                return org.apache.commons.io.IOUtils.toByteArray(inputStream);
            } catch (Exception e) {
                throw new SignatureException("XML byte'ları okunamadı", e);
            }
        }

        // ZIP dosyası ise CompressionService kullan
        return compressionService.unzipFirstEntry(inputStream);
    }
}