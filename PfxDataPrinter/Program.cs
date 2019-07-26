using System;
using System.CodeDom.Compiler;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace PfxDataPrinter
{
    internal static class Program
    {
        private const string PromptString = "PROMPT";

        private static int Main(string[] args)
        {
            byte[] pfxBytes = null;
            string password = null;
            string macPassword = null;

            if (args.Length > 0)
            {
                try
                {
                    pfxBytes = File.ReadAllBytes(args[0]);
                }
                catch
                {
                }

                if (args.Length > 1)
                {
                    if (PromptString != args[1])
                    {
                        password = args[1];
                    }
                }

                if (args.Length > 2)
                {
                    if (PromptString != args[2])
                    {
                        macPassword = args[2];
                    }
                }
                else
                {
                    macPassword = password;
                }
            }

            if (pfxBytes == null)
            {
                Console.WriteLine("Usage: PfxDataPrinter <pfxfile> [password] [macpassword]");
                Console.WriteLine();
                Console.WriteLine($"  Specify {PromptString} for both/either password to be prompted.");
                Console.WriteLine("  If no password is given and one is needed one prompt will apply to both passwords");
                Console.WriteLine();
                return 1;
            }

            try
            {
                using (IndentedTextWriter writer = new IndentedTextWriter(Console.Out, "  "))
                {
                    writer.WriteLine($"Opening {args[0]}.");
                    writer.Flush();

                    Pkcs12Info info = Pkcs12Info.Decode(pfxBytes, out int consumed, skipCopy: true);

                    writer.WriteLine($"{consumed}/{pfxBytes.Length} bytes read as a PFX.");
                    writer.WriteLine($"PFX integrity mode: {info.IntegrityMode}");

                    if (info.VerifyMac(macPassword))
                    {
                        writer.WriteLine("MAC verified with {0} password.", macPassword == null ? "default" : "provided");
                    }
                    else if (macPassword != null)
                    {
                        WriteLineWithColor(
                            ConsoleColor.Yellow,
                            writer,
                            "MAC does not verify with provided password.");
                        return 3;
                    }
                    else
                    {
                        writer.Write("Enter {0}password: ", args.Length > 1 ? "MAC " : "");
                        writer.Flush();
                        macPassword = Console.In.ReadLine();

                        if (info.VerifyMac(macPassword))
                        {
                            writer.WriteLine("MAC verified with provided password.");

                            // No password was given
                            if (args.Length == 1)
                            {
                                password = macPassword;
                            }
                        }
                        else
                        {
                            WriteLineWithColor(
                                ConsoleColor.Yellow,
                                writer,
                                "MAC does not verify with provided password.");

                            return 3;
                        }
                    }

                    writer.WriteLine();
                    writer.Indent++;

                    int i = -1;

                    foreach (Pkcs12SafeContents safeContents in info.AuthenticatedSafe)
                    {
                        i++;

                        if (i > 0)
                        {
                            writer.WriteLine();
                        }

                        writer.Indent--;
                        writer.WriteLine($"AuthenticatedSafe[{i}]:");
                        writer.Indent++;

                        PrintSafeContents(writer, safeContents, ref password);

                        writer.Indent -= 2;
                    }

                    writer.Indent--;
                }

                return 0;
            }
            catch (Exception e)
            {
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Exception:");
                Console.WriteLine(e);
                Console.ResetColor();
                return 2;
            }
        }

        private static void PrintSafeContents(IndentedTextWriter writer, Pkcs12SafeContents safeContents, ref string password)
        {
            writer.WriteLine($"ConfidentialityMode: {safeContents.ConfidentialityMode}");

            if (safeContents.ConfidentialityMode == Pkcs12ConfidentialityMode.Password)
            {
                if (password == null)
                {
                    try
                    {
                        safeContents.Decrypt(password);
                    }
                    catch (CryptographicException)
                    {
                        writer.Write("Enter password: ");
                        writer.Flush();
                        password = Console.In.ReadLine();
                    }
                }

                if (safeContents.ConfidentialityMode == Pkcs12ConfidentialityMode.Password)
                {
                    try
                    {
                        safeContents.Decrypt(password);
                    }
                    catch (CryptographicException)
                    {
                        WriteLineWithColor(
                            ConsoleColor.Red,
                            writer,
                            "Password failed to decrypt contents");

                        return;
                    }
                }
            }
            else if (safeContents.ConfidentialityMode != Pkcs12ConfidentialityMode.None)
            {
                WriteLineWithColor(
                    ConsoleColor.Yellow,
                    writer,
                    "Cannot process contents, skipping.");

                return;
            }

            writer.WriteLine("Bags:");
            writer.Indent += 2;

            int j = -1;

            foreach (Pkcs12SafeBag bag in safeContents.GetBags())
            {
                j++;

                if (j > 0)
                {
                    writer.WriteLine();
                }

                writer.Indent--;
                writer.WriteLine($"Bag[{j}] ({bag.GetType().Name}): ({bag.GetBagId().Value})");
                writer.Indent++;

                PrintBagDetails(writer, bag, ref password);

                writer.Indent--;
            }
        }

        private static void PrintBagDetails(IndentedTextWriter writer, Pkcs12SafeBag bag, ref string password)
        {
            if (bag is Pkcs12CertBag certBag)
            {
                writer.WriteLine($"IsX509Certificate: {certBag.IsX509Certificate}");

                if (certBag.IsX509Certificate)
                {
                    try
                    {
                        using (X509Certificate2 cert = certBag.GetCertificate())
                        {
                            writer.WriteLine($"Subject: {cert.Subject}");
                            writer.WriteLine($" Issuer: {cert.Issuer}");
                        }
                    }
                    catch (CryptographicException)
                    {
                        WriteLineWithColor(
                            ConsoleColor.Yellow,
                            writer,
                            "Certificate did not parse.");
                    }
                }
                else
                {
                    writer.WriteLine($"Certificate Type: {certBag.GetCertificateType().Value}");
                }
            }
            else if (bag is Pkcs12KeyBag keyBag)
            {
                try
                {
                    Pkcs8PrivateKeyInfo keyInfo = Pkcs8PrivateKeyInfo.Decode(
                        keyBag.Pkcs8PrivateKey,
                        out int keyRead,
                        skipCopy: true);

                    writer.WriteLine($"Private Key used {keyRead}/{keyBag.Pkcs8PrivateKey.Length} bytes.");

                    writer.WriteLine(
                        $"Private Key Algorithm: {keyInfo.AlgorithmId.Value} ({keyInfo.AlgorithmId.FriendlyName})");
                }
                catch (CryptographicException)
                {
                    WriteLineWithColor(
                        ConsoleColor.Yellow,
                        writer,
                        "Private Key was not a valid PKCS#8 PrivateKeyInfo");
                }
            }
            else if (bag is Pkcs12ShroudedKeyBag shroudedBag)
            {
                if (password == null)
                {
                    try
                    {
                        Pkcs8PrivateKeyInfo.DecryptAndDecode(
                            password,
                            shroudedBag.EncryptedPkcs8PrivateKey,
                            out _);
                    }
                    catch (CryptographicException)
                    {
                        writer.Write("Enter password: ");
                        writer.Flush();
                        password = Console.In.ReadLine();
                    }
                }

                try
                {
                    Pkcs8PrivateKeyInfo keyInfo = Pkcs8PrivateKeyInfo.DecryptAndDecode(
                        password,
                        shroudedBag.EncryptedPkcs8PrivateKey,
                        out int privateKeyRead);

                    writer.WriteLine(
                        $"Private Key used {privateKeyRead}/{shroudedBag.EncryptedPkcs8PrivateKey.Length} bytes.");

                    writer.WriteLine(
                        $"Private Key Algorithm: {keyInfo.AlgorithmId.Value} ({keyInfo.AlgorithmId.FriendlyName})");
                }
                catch (CryptographicException)
                {
                    WriteLineWithColor(
                        ConsoleColor.Yellow,
                        writer,
                        "Private Key was not a valid PKCS#8 EncryptedPrivateKeyInfo or it did not decrypt.");
                }
            }
            else if (bag is Pkcs12SecretBag secretBag)
            {
                writer.WriteLine($"Secret Type: {secretBag.GetSecretType().Value}");
            }

            writer.WriteLine("Attributes:");
            writer.Indent++;
            bool firstAttr = true;

            foreach (CryptographicAttributeObject attrGroup in bag.Attributes)
            {
                foreach (AsnEncodedData attr in attrGroup.Values)
                {
                    if (!firstAttr)
                    {
                        writer.WriteLine();
                    }

                    firstAttr = false;

                    PrintAttribute(writer, attr);
                }
            }

            if (firstAttr)
            {
                writer.WriteLine("No attributes present.");
            }
        }

        private static void PrintAttribute(TextWriter writer, AsnEncodedData attr)
        {
            writer.WriteLine($"Type: {attr.GetType().Name} ({attr.Oid.Value})");

            if (attr is Pkcs9LocalKeyId keyId)
            {
                writer.WriteLine($"Value: {keyId.KeyId.ToHex()}");
            }
            else
            {
                byte[] rawData = attr.RawData;
                writer.WriteLine($"Value Length: {rawData.Length}");

                if (rawData.Length > 12)
                {
                    writer.WriteLine($"Value: {rawData.AsSpan(0, 10).ToHex()}...");
                }
                else
                {
                    writer.WriteLine($"Value: {rawData.ToHex()}");
                }
            }
        }

        private static void WriteLineWithColor(ConsoleColor color, TextWriter writer, string message)
        {
            writer.Flush();
            Console.ForegroundColor = color;
            writer.WriteLine(message);
            writer.Flush();
            Console.ResetColor();
        }

        private static string ToHex(this byte[] bytes)
        {
            return ToHex(bytes.AsSpan());
        }

        private static string ToHex(this ReadOnlyMemory<byte> bytes)
        {
            return ToHex(bytes.Span);
        }

        private static string ToHex(this Span<byte> bytes)
        {
            return ToHex((ReadOnlySpan<byte>)bytes);
        }

        private static string ToHex(this ReadOnlySpan<byte> bytes)
        {
            StringBuilder builder = new StringBuilder(bytes.Length * 2);

            for (int i = 0; i < bytes.Length; i++)
            {
                builder.Append(bytes[i].ToString("X2"));
            }

            return builder.ToString();
        }
    }
}
