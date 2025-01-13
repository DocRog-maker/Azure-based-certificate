
// This sample is based on the Apryse DigitalSignature sample

using System;
using System.IO;

using pdftron;
using pdftron.PDF;
using pdftron.PDF.Annots;
using pdftron.SDF;
using pdftron.Crypto;
using System.Security.Cryptography.X509Certificates;
using Azure.Security.KeyVault.Certificates;
using Azure.Identity;
using Azure.Security.KeyVault.Keys.Cryptography;
using System.Linq;

namespace DigitalSignaturesTestCS
{

    class Class1
    {
        //The paths where the source file is located and the destination should be placed
        static string input_path = "../../../../../TestFiles/";
        static string output_path = "../../../../../TestFiles/Output/";


        static void CustomSigningAPIZAzure(string doc_path,
    string cert_field_name,
    string appearance_image_path,
    DigestAlgorithm.Type digest_algorithm_type,
    string output_path)
        {
            using (PDFDoc doc = new PDFDoc(doc_path))
            {
                Page page1 = doc.GetPage(1);

                DigitalSignatureField digsig_field = doc.CreateDigitalSignatureField(cert_field_name);
                SignatureWidget widgetAnnot = SignatureWidget.Create(doc, new Rect(143, 287, 219, 306), digsig_field);
                page1.AnnotPushBack(widgetAnnot);

                // (OPTIONAL) Add an appearance to the signature field.
                Image img = Image.Create(doc, appearance_image_path);
                widgetAnnot.CreateSignatureAppearance(img);

                // Create a digital signature dictionary inside the digital signature field, in preparation for signing.
                digsig_field.CreateSigDictForCustomSigning("Adobe.PPKLite",DigitalSignatureField.SubFilterType.e_adbe_pkcs7_detached, 7500); 
                // For security reasons, set the contents size to a value greater than but as close as possible to the size you expect your final signature to be, in bytes.
                // ... or, if you want to apply a certification signature, use CreateSigDictForCustomCertification instead.

                // (OPTIONAL) Set the signing time in the signature dictionary, if no secure embedded timestamping support is available from your signing provider.
                Date current_date = new Date();
                current_date.SetCurrentTime();
                digsig_field.SetSigDictTimeOfSigning(current_date);

                var s = digsig_field.GetSigningTime();
                doc.Save(output_path, SDFDoc.SaveOptions.e_incremental);

                // Digest the relevant bytes of the document in accordance with ByteRanges surrounding the signature.
                byte[] pdf_digest = digsig_field.CalculateDigest(digest_algorithm_type);

                String tenantId = System.Configuration.ConfigurationManager.AppSettings["tenantId"];
                String clientId = System.Configuration.ConfigurationManager.AppSettings["clientId"];
                String secret = System.Configuration.ConfigurationManager.AppSettings["secret"];
                String vaultUri = System.Configuration.ConfigurationManager.AppSettings["vaultUri"];
                String certificateName = System.Configuration.ConfigurationManager.AppSettings["certificateName"];

                ClientSecretCredential credential = new ClientSecretCredential(tenantId, clientId, secret);

                //Create certificate client.
                CertificateClient certificateClient = new CertificateClient(new Uri(vaultUri), credential);

                //Get the certificate with public key.
                KeyVaultCertificateWithPolicy certificateWithPolicy = certificateClient.GetCertificate(certificateName);

                //Create and return the X509Certificate2.
                var cert = new X509Certificate2(certificateWithPolicy.Cer);
                pdftron.Crypto.X509Certificate signer_cert = new pdftron.Crypto.X509Certificate(cert.Export(X509ContentType.Cert));

                //Build the certificate chain.
                X509Chain chain = new X509Chain();
                chain.Build(cert);

                pdftron.Crypto.X509Certificate[] chain_certs = { };
                for (int i = 0; i < chain.ChainElements.Count; i++)
                {
                    var c = chain.ChainElements[i].Certificate.Export(X509ContentType.Cert);
                    chain_certs.Append(new pdftron.Crypto.X509Certificate(c));
                }

                // You could add PAdES attributes if you want (see the original sample), for now, let's keep things simple
                // The signedAttrs are certain attributes that become protected by their inclusion in the signature.
                byte[] signedAttrs = DigitalSignatureField.GenerateCMSSignedAttributes(pdf_digest);

                // Calculate the digest of the signedAttrs (i.e. not the PDF digest, this time).
                byte[] signedAttrs_digest = DigestAlgorithm.CalculateDigest(digest_algorithm_type, signedAttrs);

                ////////////////////////////// custom digest signing starts ////////////////////////////
                //// At this point, you can sign the digest (for example, with HSM). We use our own SignDigest function instead here as an example,
                //// which you can also use for your purposes if necessary as an alternative to the handler/callback APIs (i.e. Certify/SignOnNextSave).
                string cryptoClientUri = System.Configuration.ConfigurationManager.AppSettings["cryptoClientUri"];

                CryptographyClient client = new CryptographyClient(new Uri(cryptoClientUri), credential);

                //Need to map from the digest type that Apryse uses to that used by Azure
                SignatureAlgorithm algorithm = SignatureAlgorithm.RS256;
                switch (digest_algorithm_type)
                {
                    case DigestAlgorithm.Type.e_sha256:
                        algorithm = SignatureAlgorithm.RS256;

                        break;
                    case DigestAlgorithm.Type.e_sha512:
                        algorithm = SignatureAlgorithm.RS512;
                        break;
                    case DigestAlgorithm.Type.e_sha384:
                        algorithm = SignatureAlgorithm.RS384;
                        break;
                    default:
                        throw new NotImplementedException();
                }

                var res = client.Sign(algorithm, signedAttrs_digest);
                var signature_value = res.Signature;
                /////////////////////////// custom digest signing ends //////////////////////////////

                // Then, create ObjectIdentifiers for the algorithms you have used.
                // Here we use digest_algorithm_type (usually SHA256) for hashing, and RSAES-PKCS1-v1_5 (specified in the private key) for signing.
                ObjectIdentifier digest_algorithm_oid = new ObjectIdentifier(digest_algorithm_type);
                ObjectIdentifier signature_algorithm_oid = new ObjectIdentifier(ObjectIdentifier.Predefined.e_RSA_encryption_PKCS1);

                // Then, put the CMS signature components together.
                byte[] cms_signature = DigitalSignatureField.GenerateCMSSignature(
                    signer_cert, chain_certs, digest_algorithm_oid, signature_algorithm_oid,
                    signature_value, signedAttrs);

                // Write the signature to the document.
                doc.SaveCustomSignature(cms_signature, digsig_field, output_path);
            }
            Console.Out.WriteLine("================================================================================");
        }



        private static pdftron.PDFNetLoader pdfNetLoader = pdftron.PDFNetLoader.Instance();
        static Class1() { }

        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main(string[] args)
        {
            // Initialize PDFNetC
            PDFNet.Initialize(PDFTronLicense.Key);

            bool result = true;

            try
            {
                CustomSigningAPIZAzure(input_path + "waiver.pdf",
                    "PDFTronApprovalSig",
                    input_path + "signature.jpg",
                    DigestAlgorithm.Type.e_sha256,
                    output_path + "waiver_custom_signed-12.pdf");
            }
            catch (Exception e)
            {
                Console.Error.WriteLine(e);
                result = false;
            }


            //////////////////// End of tests. ////////////////////
            PDFNet.Terminate();
            if (result)
            {
                Console.Out.WriteLine("Tests successful.\n==========");
            }
            else
            {
                Console.Out.WriteLine("Tests FAILED!!!\n==========");
            }
        }
    }
}
