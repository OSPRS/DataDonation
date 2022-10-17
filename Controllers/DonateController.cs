using DataDonation.Database;
using DataDonation.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Text.Json;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;
using System.Linq;
using System.Text;

namespace DataDonation.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class DonateController : ControllerBase
    {
        private readonly ILogger<DonateController> _logger;
        private readonly DatabaseContext _dbcontext;

        public DonateController(ILogger<DonateController> logger, DatabaseContext dbcontext)
        {
            _logger = logger;
            _dbcontext = dbcontext;
        }

        /// <summary>
        /// Submits a data Donation
        /// </summary>
        /// <returns></returns>
        [HttpPost]
        public async Task<ActionResult> Submit(JsonElement data)
        {
            // TODO: Add validation
            var dataDonation = new DataDonationEntry(
                Guid.NewGuid(), DateTime.Now, JsonSerializer.Serialize(data));
            await _dbcontext.DataDonationEntries.AddAsync(dataDonation);
            await _dbcontext.SaveChangesAsync();


            RSA rsa = RSA.Create();
            rsa.KeySize = 2048;

            string priv = Convert.ToBase64String(rsa.ExportPkcs8PrivateKey(), Base64FormattingOptions.InsertLineBreaks);
            string publicKey = Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo(), Base64FormattingOptions.InsertLineBreaks);

            string private_PEM = $"-----BEGIN PRIVATE KEY-----\n{priv}\n-----END PRIVATE KEY-----";
            string public_PEM = $"-----BEGIN PUBLIC KEY-----\n{publicKey}\n-----END PUBLIC KEY-----";

            // Console.WriteLine("Public Key: " + public_PEM);
            // Console.WriteLine("Private Key: " + private_PEM);



            private_PEM = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDU7YgH7NAfTUnoxb5mnIf+UQ2evWfL160YeLsfbG+j+XjJ4lchCDQfysl+nn3DG0QvRic7MH1IUHI0TCgOx3sPTc+8s6G2HrrTlin1OTaZPF/1gV1cP6+haGMie+X7Zf43Lw5Ry105LU//cY4Gfj4AcF3pALIzFFSWM7HuSHNORZyQ9p+ToW32TVbORWyjQgP5ivnneDhU6fxQEhg//rXHkY/9aVa9ScqdDDnH6BcRgQFbS4nnM2qSH8AHznVJaxYKg/MPY+IcoatTKBFVLONlrV8mE/59r/b1LFacfoiISatVcfJNiRniBVhMtffVwq/rIz3DgFyAJ7YbLrm/I/rdAgMBAAECggEAfNDUqdie04qJ5cJs71eYvHKk6kWbH7nJBQxYnH4DH3rw3F8qtflKHMzRusCLdiB4osGb461z8zz9BT0TSj6TG5CAUtx10f1HhRqEc/Ra1g63LYHsyVOnz5USb7dzRCAwmgaifT4Z4pd2SoY1PAcqrzUvR5OZ4ilrwDSDe+vKc7l2e5WPbbT+9ukBux5ab+u1m5koRpHM8vLCbO4/Dv/jQFRm2bYynV6J/ptG2iTDi0A97xWMvAlDa2iUThZAoA3/iq1nO8Ku4Nl4BXKM64ec7+fX3WTyl+S9NRwiGjEV8nJZJdVdssUC1+hJh8hn1sKhl7Y9P34X2ZIJeGyXTSI0oQKBgQD29GsTUzW5HALy9cbqDAgoH+uzGN+5KLJKVkn2y3cpKiuYq3patOQXX8/EwqWkMh/OwpKZFJaPsNZB4eWfcWhcuR2Wxi4Xc5bQ5pjS+CxmNJ1nVNoUPrAQQ+mwQM0KJjnaFdtNAF9TFnrvP+a5lhN86D5mpikVakLcWHeWuWTKyQKBgQDcug70zbcg6zd0QfC1jZG+Nui7SLATgjwY8g3VTqjyNw8rhCTx8mLP9XdT9zi/mTgFdFJtY+v2rujN3JdyVRxxHmcdNMXnUUJKHzCi6Vzl+aKSQrsGTShlWBImX2ddll0DN+iPKeTiCXIa2B0BLLkURqUg9rWG6bAG7k1mFoJldQKBgA370yBaAt3Df0tArY3NNp0HCbKvguOaMVZSQofuB4ZWM/fGJfyC57OHIl2y4+xDRlfP3rs6Vjg2vDsoznbT1iQB+3HxMOT1D6IunJK9qM30xsD2Jg8laZTSM6ZeVP3xIi9+M1fN4Jf02us3RBpYLCxTfk0TtZnX1Ydinwry3ok5AoGBAIzPwZTY29gLVrA7FOWtr+mKPASmhXWcotxDJyIKcWs8Rtg7EBqtx+3lKcAOOky44W1RXPheQ3127hvOe2s78s4TWDLgpNRCGakRpsR3XYV1MQpfudJ2TKwCeGm0eUvSDfpso1cZoeO1pO6NKkvCjTvrKZMS8JFl6Z8yTXwwJfW1AoGBAMZGHZ9iawLYqh9ho8JWSMlxvV+aQouoqLx5Ica0jfCQIT/fykqQa5QxD05WkBkK3bPapxFMifEm7+jGzKNDCcPRQwrUdJHpqPzuEsNux9s6LojKolCmEXeZS7f18dqK0YNGJeuPkCh4vlJze7iAhj6lb6UhcmkCtDkR+kMza4el\n-----END PRIVATE KEY-----";
            public_PEM = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1O2IB+zQH01J6MW+ZpyH/lENnr1ny9etGHi7H2xvo/l4yeJXIQg0H8rJfp59wxtEL0YnOzB9SFByNEwoDsd7D03PvLOhth6605Yp9Tk2mTxf9YFdXD+voWhjInvl+2X+Ny8OUctdOS1P/3GOBn4+AHBd6QCyMxRUljOx7khzTkWckPafk6Ft9k1WzkVso0ID+Yr553g4VOn8UBIYP/61x5GP/WlWvUnKnQw5x+gXEYEBW0uJ5zNqkh/AB851SWsWCoPzD2PiHKGrUygRVSzjZa1fJhP+fa/29SxWnH6IiEmrVXHyTYkZ4gVYTLX31cKv6yM9w4BcgCe2Gy65vyP63QIDAQAB\n-----END PUBLIC KEY-----";
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

                var privateKeyBlocks = private_PEM.Split("-", StringSplitOptions.RemoveEmptyEntries);
                var privateKeyBytes = Convert.FromBase64String(privateKeyBlocks[1]);

                var decryptRSA = RSA.Create();
                decryptRSA.ImportPkcs8PrivateKey(privateKeyBytes, out _);

                var aes_Key_Bytes = decryptRSA.Decrypt(bytesCypherText, RSAEncryptionPadding.OaepSHA256);

                //get our original plainText back...
                var aesKey = System.Text.Encoding.Unicode.GetString(aes_Key_Bytes);

                // Declare the string used to hold
                // the decrypted text.
                string plaintext = null;

                // Create an Aes object
                // with the specified key and IV.
                using (AesGcm aesAlg = new AesGcm(aes_Key_Bytes))
                {

                    // According to https://pilabor.com/series/dotnet/js-gcm-encrypt-dotnet-decrypt/

                    var tagSizeBytes = 16; // 128 bit encryption / 8 bit = 16 bytes
                    var ivSizeBytes = 12; // 12 bytes iv
                    var cipherSize = encryptedAnswers_Bytes.Length - tagSizeBytes; // - ivSizeBytes;
                    var plaintextBytes = new byte[cipherSize];

                    var tagStart = cipherSize; // + ivSizeBytes


                    var tag = encryptedAnswers_Bytes.Skip(cipherSize).Take(tagSizeBytes).ToArray();
                    var cipherBytes = encryptedAnswers_Bytes.Take(cipherSize).ToArray();
                    aesAlg.Decrypt(iv_Bytes, cipherBytes, tag, plaintextBytes);
                    Console.WriteLine(Encoding.UTF8.GetString(plaintextBytes));

                }


            }

            return Ok();
        }
    }
}
