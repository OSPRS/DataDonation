using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CommandLine;
using CsvHelper;
using DB;
using DB.Models;
using Microsoft.EntityFrameworkCore;
using Sharprompt;

namespace DecryptTool
{
    public class Program
    {
        static string keysPath = "keys";
        static string keysPrivateFileName = "private_key.pem";
        static string keysPublicFileName = "public_key.pem";

        public class Options
        {
            [Option('v', "verbose", Required = false, HelpText = "Set output to verbose messages.")]
            public bool Verbose { get; set; }

            [Option("connectionString", Required = false, HelpText = "Connection String to encrypted Database.")]
            public string? ConnectionString
            {
                get; set;
            }

            [Option("privateKey", Required = false, HelpText = "Private key for encrypted Data.")]
            public string? PrivateKey
            {
                get; set;
            }
        }

        [Verb("keygen", HelpText = "Generate Keys for encryption/decryption.")]
        public class GenerateKeys
        {
            //clone options here
        }

        public static void Main(string[] args)
        {
            Parser.Default.ParseArguments<Options, GenerateKeys>(args)
                   .MapResult(
                     (Options opts) => DecryptData(opts),
                     (GenerateKeys opts) => GenerateKey(opts),
                    error => Task.FromResult(1));
        }

        public static async Task<int> DecryptData(Options opts)
        {
            string? connectionString = opts.ConnectionString;
            if (connectionString == null)
            {
                connectionString = Prompt.Input<string>("Supply Connection String:", "server=localhost;database=datadonation;user=root;password=example;OldGuids=true");
            }

            var serverVersion = new MySqlServerVersion(ServerVersion.AutoDetect(connectionString));
            var dbContext = new DatabaseContext(new DbContextOptionsBuilder().UseMySql(connectionString, serverVersion).Options);
            await dbContext.Database.CanConnectAsync();

            string? privateKeyPath = opts.PrivateKey;
            if (privateKeyPath == null)
            {
                privateKeyPath = Prompt.Input<string>("Supply Private Key Path:", keysPath);
            }

            var privateKey = await File.ReadAllTextAsync(Path.Combine(keysPath, keysPrivateFileName));
            var privateKeyBlocks = privateKey.Split("-", StringSplitOptions.RemoveEmptyEntries);
            var privateKeyBytes = Convert.FromBase64String(privateKeyBlocks[1]);

            var decryptRSA = RSA.Create();
            decryptRSA.ImportPkcs8PrivateKey(privateKeyBytes, out _);

            var records = new List<DataDonationEntry> { };
            await dbContext.DataDonationEntries.ForEachAsync(entry =>
            {
                records.Add(new DataDonationEntry(
                 entry.Id,
                entry.date,
                Decrypt(JsonSerializer.Deserialize<JsonElement>(entry.data), decryptRSA)
                ));
            });


            using (var writer = new StreamWriter("cleartext_data.csv"))
            using (var csv = new CsvWriter(writer, CultureInfo.InvariantCulture))
            {
                csv.WriteRecords(records);
            }

            return 0;
        }

        public static async Task<int> GenerateKey(GenerateKeys opts)
        {
            RSA rsa = RSA.Create();
            rsa.KeySize = 2048;

            string priv = Convert.ToBase64String(rsa.ExportPkcs8PrivateKey(), Base64FormattingOptions.InsertLineBreaks);
            string publicKey = Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo(), Base64FormattingOptions.InsertLineBreaks);

            if (!Directory.Exists(keysPath))
            {
                Directory.CreateDirectory(keysPath);
            }
            else
            {
                var answer = Prompt.Confirm($"The directory ('{keysPath}') already exists. Should existing keys be overwritten?", defaultValue: false);
                if (!answer)
                {
                    return 0;
                }
            }

            string private_PEM = $"-----BEGIN PRIVATE KEY-----\n{priv}\n-----END PRIVATE KEY-----";
            await File.WriteAllTextAsync(Path.Combine(keysPath, keysPrivateFileName), private_PEM);

            string public_PEM = $"-----BEGIN PUBLIC KEY-----\n{publicKey}\n-----END PUBLIC KEY-----";
            await File.WriteAllTextAsync(Path.Combine(keysPath, keysPublicFileName), public_PEM);

            Console.WriteLine("Generated Keys in 'out' Folder!");
            Console.WriteLine("WARNING! These keys are made for testing purposes. Do use a cryptographically more secure application for real world usage, e.g. 'openssl'.");
            return 0;
        }

        public static string Decrypt(JsonElement data, RSA privateKey)
        {
            JsonElement encryptedKey;
            JsonElement iv;
            JsonElement encryptedAnswers;
            if (data.TryGetProperty("encryptedKey", out encryptedKey)
                 && data.TryGetProperty("iv", out iv)
                 && data.TryGetProperty("encryptedAnswers", out encryptedAnswers))
            {


                Console.WriteLine(encryptedKey.GetString());
                Console.WriteLine(iv.GetString());

                //first, get our bytes back from the base64 string ...
                var bytesCypherText = Convert.FromBase64String(encryptedKey.GetString());
                var iv_Bytes = Convert.FromBase64String(iv.GetString());
                var encryptedAnswers_Bytes = Convert.FromBase64String(encryptedAnswers.GetString());

                var aes_Key_Bytes = privateKey.Decrypt(bytesCypherText, RSAEncryptionPadding.OaepSHA256);

                //var aesKey = System.Text.Encoding.Unicode.GetString(aes_Key_Bytes);

                using (AesGcm aesAlg = new AesGcm(aes_Key_Bytes))
                {
                    // According to https://pilabor.com/series/dotnet/js-gcm-encrypt-dotnet-decrypt/

                    var tagSizeBytes = 16; // 128 bit encryption / 8 bit = 16 bytes
                    var cipherSize = encryptedAnswers_Bytes.Length - tagSizeBytes;
                    var plaintextBytes = new byte[cipherSize];
                    var tagStart = cipherSize;

                    var tag = encryptedAnswers_Bytes.Skip(cipherSize).Take(tagSizeBytes).ToArray();
                    var cipherBytes = encryptedAnswers_Bytes.Take(cipherSize).ToArray();
                    aesAlg.Decrypt(iv_Bytes, cipherBytes, tag, plaintextBytes);

                    string decryptedText = Encoding.UTF8.GetString(plaintextBytes);
                    //Console.WriteLine(decryptedText);
                    return decryptedText;
                }
            }
            else
            {
                throw new Exception("Data could not be encrypted. (Missing encyptedKey etc.");
            }
        }
    }
}