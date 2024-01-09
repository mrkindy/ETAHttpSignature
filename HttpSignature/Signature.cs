using System;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ess;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using WebSocketSharp;
using WebSocketSharp.Server;
using Newtonsoft.Json;

namespace HttpSignature
{
    public class Signature : WebSocketBehavior
    {
        private readonly string[] drivers = { "ePass2003", "WD_PROXKEY", "Egypt Trust" };

        private string DllLibPath = "eps2003csp11.dll"; // Use "aetpkss1.dll" For G&D StarSign
        
        private string TokenPin = "00000000";
        
        private string TokenCertificate = "Egypt Trust Sealing CA"; // Use "MCDR CA" For Misr Clearing Company Certificate 

        protected override void OnMessage(MessageEventArgs e)
        {
            SignRequest data = JsonConvert.DeserializeObject<SignRequest>(e.Data);

            if (string.IsNullOrEmpty(data.Type))
            {
                Console.WriteLine("[Type] attribute can't be null or empty!");
                Send("{\"status\":0,\"message\":\"[Type] attribute can't be null or empty!\"}");
                return;
            }

            if (data.Type == "LIST_SUPPORTED_DRIVERS")
            {   
                Console.WriteLine("Supported Drivers:");

                string drivers_list = "";
                
                foreach (string driver in drivers)
                {
                    Console.WriteLine("- " + driver);
                    drivers_list += (drivers_list == "" ? "" : ",") + "\"" + driver + "\"";
                }

                Send("{\"status\":1,\"message\":\"List of Supported Drivers.\",\"type\":\"" + data.Type + "\",\"data\":[" + drivers_list + "]}");
                return;
            }

            if (data.Type == "SIGN_DOCUMENT")
            {
                if (!IdentifyDriver(data)) return;

                if (string.IsNullOrEmpty(data.Password))
                {
                    TokenPin = Program.ShowDialog("طلب توقيع", "يرجى ادخل كلمة المرور");
                }
                else
                {
                    TokenPin = data.Password;
                }

                try
                {
                    string cades = SignWithCMS(data.Document);

                    Console.WriteLine("Invoice Signed.");

                    Send("{\"status\":1,\"message\":\"Invoice Signed.\",\"cades\":\"" + cades + "\"}");
                }
                catch (Exception signException)
                {
                    Console.WriteLine("Failed to sign document!");
                    Console.WriteLine(signException.GetBaseException().Message);
                    Send("{\"status\":0,\"message\":\"Failed to sign document!\",\"exception_message\":\"" + signException.GetBaseException().Message + "\"}");
                }
            }
        }

        private bool IdentifyDriver(SignRequest data)
        {
            if (data.Driver == "ePass2003")
            {
                DllLibPath = "eps2003csp11.dll";
                TokenCertificate = "Egypt Trust Sealing CA"; //needs to be reviewd
            } else if (data.Driver == "WD_PROXKEY")
            {
                DllLibPath = ""; //needs to be reviewd
                TokenCertificate = ""; //needs to be reviewd
            } else if (data.Driver == "Egypt Trust")
            {
                DllLibPath = ""; //needs to be reviewd
                TokenCertificate = ""; //needs to be reviewd
            } else
            {
                Console.WriteLine("You didn't select predefined driver.");

                if (string.IsNullOrEmpty(data.DllLibPath) || string.IsNullOrEmpty(data.TokenCertificate))
                {
                    Console.WriteLine("[DllLibPath] and [TokenCertificate] attributes can't be null or empty!");
                    Send("{\"status\":0,\"message\":\"You didn't select predefined driver, [DllLibPath] and [TokenCertificate] attributes can't be null or empty!\"}");
                    return false;
                }

                DllLibPath = data.DllLibPath;
                TokenCertificate = data.TokenCertificate;
            }

            Console.WriteLine("Identified Driver:");
            Console.WriteLine("- DllLibPath:" + DllLibPath);
            Console.WriteLine("- TokenCertificate:" + TokenCertificate);

            return true;
        }

        private byte[] HashBytes(byte[] input)
        {
            using (SHA256 sha = SHA256.Create())
            {
                return sha.ComputeHash(input);
            }
        }

        public string SignWithCMS(String serializedJson)
        {
            byte[] data = Encoding.UTF8.GetBytes(serializedJson);
            
            Pkcs11InteropFactories factories = new Pkcs11InteropFactories();

            try
            {
                using (IPkcs11Library pkcs11Library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, DllLibPath, AppType.MultiThreaded))
                {
                    ISlot slot = pkcs11Library.GetSlotList(SlotsType.WithTokenPresent).FirstOrDefault();

                    if (slot is null)
                    {
                        Console.WriteLine("NO_SOLTS_FOUND");
                        throw new Exception("NO_SOLTS_FOUND");
                    }

                    ITokenInfo tokenInfo = slot.GetTokenInfo();

                    ISlotInfo slotInfo = slot.GetSlotInfo();

                    using (var session = slot.OpenSession(SessionType.ReadWrite))
                    {
                        try
                        {
                            session.Login(CKU.CKU_USER, Encoding.UTF8.GetBytes(TokenPin));
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("PASSWORD_INVAILD");
                            Console.WriteLine(e.GetBaseException().Message);
                            throw new Exception("PASSWORD_INVAILD");
                        }

                        var certificateSearchAttributes = new List<IObjectAttribute>()
                        {
                            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE),
                            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                            session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CERTIFICATE_TYPE, CKC.CKC_X_509)
                        };

                        IObjectHandle certificate = session.FindAllObjects(certificateSearchAttributes).FirstOrDefault();

                        if (certificate is null)
                        {
                            Console.WriteLine("CERTIFICATE_NOT_FOUND");
                            throw new Exception("CERTIFICATE_NOT_FOUND");
                        }

                        X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);

                        store.Open(OpenFlags.MaxAllowed);

                        // find cert by thumbprint
                        var foundCerts = store.Certificates.Find(X509FindType.FindByIssuerName, TokenCertificate, false);

                        //var foundCerts = store.Certificates.Find(X509FindType.FindBySerialNumber, "2b1cdda84ace68813284519b5fb540c2", true);

                        if (foundCerts.Count == 0)
                        {
                            Console.WriteLine("NO_DEVICE_DETECTED");
                            throw new Exception("NO_DEVICE_DETECTED");
                        }

                        var certForSigning = foundCerts[0];

                        store.Close();

                        ContentInfo content = new ContentInfo(new Oid("1.2.840.113549.1.7.5"), data);

                        SignedCms cms = new SignedCms(content, true);

                        EssCertIDv2 bouncyCertificate = new EssCertIDv2(new Org.BouncyCastle.Asn1.X509.AlgorithmIdentifier(new DerObjectIdentifier("1.2.840.113549.1.9.16.2.47")), this.HashBytes(certForSigning.RawData));

                        SigningCertificateV2 signerCertificateV2 = new SigningCertificateV2(new EssCertIDv2[] { bouncyCertificate });

                        CmsSigner signer = new CmsSigner(certForSigning);

                        signer.DigestAlgorithm = new Oid("2.16.840.1.101.3.4.2.1");

                        signer.SignedAttributes.Add(new Pkcs9SigningTime(DateTime.UtcNow));
                        signer.SignedAttributes.Add(new AsnEncodedData(new Oid("1.2.840.113549.1.9.16.2.47"), signerCertificateV2.GetEncoded()));

                        cms.ComputeSignature(signer);

                        var output = cms.Encode();

                        return Convert.ToBase64String(output);
                    }
                }
            }
            catch (Exception e)
            {
                throw e;
            }
        }

        public void ListCertificates()
        {
            X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.MaxAllowed);
            X509Certificate2Collection collection = (X509Certificate2Collection)store.Certificates;
            X509Certificate2Collection fcollection = (X509Certificate2Collection)collection.Find(X509FindType.FindBySerialNumber, "2b1cdda84ace68813284519b5fb540c2", true);
            foreach (X509Certificate2 x509 in fcollection)
            {
                try
                {
                    byte[] rawdata = x509.RawData;
                    Console.WriteLine("Content Type: {0}{1}", X509Certificate2.GetCertContentType(rawdata), Environment.NewLine);
                    Console.WriteLine("Friendly Name: {0}{1}", x509.FriendlyName, Environment.NewLine);
                    Console.WriteLine("Certificate Verified?: {0}{1}", x509.Verify(), Environment.NewLine);
                    Console.WriteLine("Simple Name: {0}{1}", x509.GetNameInfo(X509NameType.SimpleName, true), Environment.NewLine);
                    Console.WriteLine("Signature Algorithm: {0}{1}", x509.SignatureAlgorithm.FriendlyName, Environment.NewLine);
                    Console.WriteLine("Public Key: {0}{1}", x509.PublicKey.Key.ToXmlString(false), Environment.NewLine);
                    Console.WriteLine("Certificate Archived?: {0}{1}", x509.Archived, Environment.NewLine);
                    Console.WriteLine("Length of Raw Data: {0}{1}", x509.RawData.Length, Environment.NewLine);
                    x509.Reset();
                }
                catch (CryptographicException ex)
                {
                    Console.WriteLine("Information could not be written out for this certificate.");
                    throw ex;
                }
            }
            store.Close();
        }
    }
}