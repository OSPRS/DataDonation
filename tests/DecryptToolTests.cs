using Xunit;
using System.Text.Json;
using System.Security.Cryptography;

namespace DecryptTool.Tests
{
    public class DecryptToolTests
    {
        [Fact()]
        public void DecryptTest()
        {
            var json = JsonSerializer.Deserialize<JsonElement>("""{"encryptedAnswers":"1C6oeBKm6/hjIRT+E2BYrQD+2+oD7op7iiCmyijPVg==","encryptedKey":"X2+sH9d+tQTHjdTGJ6X9vBewtgHIwwPQW46hb0dM3MtjJrj1jWrrb6LZDWgQkxlh485Rz6ica8Tg0YFWNHvNThbaufAbGJfFIGz38ZZXMm/9KnwTQJgbfL9ldCYfJi99Q9iCJFDlKETVDq9c0Xf7GxvbLHufREJ8PJYfZvCEjq04lPjXbHo8Hs9m2jijZSWBwbfjRpiWYu4i1cOimKBIJS0ZpgsT7mn2lZ+fQpE7RJKOML5I1KTlnm4KeO2S9u4mA7ysWPCy01GY1UFqkHYvy5wy/C/34IQilygSuA3VX+aTB8Zt9kLgBjp8otthB87CmXr77knNCiGv9FS6ObSyXQ==","iv":"rmLOHTCP4CnqqA26","signingKey":"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1O2IB+zQH01J6MW+ZpyH/lENnr1ny9et\nGHi7H2xvo/l4yeJXIQg0H8rJfp59wxtEL0YnOzB9SFByNEwoDsd7D03PvLOhth6605Yp9Tk2mTxf\n9YFdXD+voWhjInvl+2X+Ny8OUctdOS1P/3GOBn4+AHBd6QCyMxRUljOx7khzTkWckPafk6Ft9k1W\nzkVso0ID+Yr553g4VOn8UBIYP/61x5GP/WlWvUnKnQw5x+gXEYEBW0uJ5zNqkh/AB851SWsWCoPz\nD2PiHKGrUygRVSzjZa1fJhP+fa/29SxWnH6IiEmrVXHyTYkZ4gVYTLX31cKv6yM9w4BcgCe2Gy65\nvyP63QIDAQAB\n-----END PUBLIC KEY-----"}""");
            var privateKeyBytes = Convert.FromBase64String("MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDU7YgH7NAfTUnoxb5mnIf+UQ2evWfL160YeLsfbG+j+XjJ4lchCDQfysl+nn3DG0QvRic7MH1IUHI0TCgOx3sPTc+8s6G2HrrTlin1OTaZPF/1gV1cP6+haGMie+X7Zf43Lw5Ry105LU//cY4Gfj4AcF3pALIzFFSWM7HuSHNORZyQ9p+ToW32TVbORWyjQgP5ivnneDhU6fxQEhg//rXHkY/9aVa9ScqdDDnH6BcRgQFbS4nnM2qSH8AHznVJaxYKg/MPY+IcoatTKBFVLONlrV8mE/59r/b1LFacfoiISatVcfJNiRniBVhMtffVwq/rIz3DgFyAJ7YbLrm/I/rdAgMBAAECggEAfNDUqdie04qJ5cJs71eYvHKk6kWbH7nJBQxYnH4DH3rw3F8qtflKHMzRusCLdiB4osGb461z8zz9BT0TSj6TG5CAUtx10f1HhRqEc/Ra1g63LYHsyVOnz5USb7dzRCAwmgaifT4Z4pd2SoY1PAcqrzUvR5OZ4ilrwDSDe+vKc7l2e5WPbbT+9ukBux5ab+u1m5koRpHM8vLCbO4/Dv/jQFRm2bYynV6J/ptG2iTDi0A97xWMvAlDa2iUThZAoA3/iq1nO8Ku4Nl4BXKM64ec7+fX3WTyl+S9NRwiGjEV8nJZJdVdssUC1+hJh8hn1sKhl7Y9P34X2ZIJeGyXTSI0oQKBgQD29GsTUzW5HALy9cbqDAgoH+uzGN+5KLJKVkn2y3cpKiuYq3patOQXX8/EwqWkMh/OwpKZFJaPsNZB4eWfcWhcuR2Wxi4Xc5bQ5pjS+CxmNJ1nVNoUPrAQQ+mwQM0KJjnaFdtNAF9TFnrvP+a5lhN86D5mpikVakLcWHeWuWTKyQKBgQDcug70zbcg6zd0QfC1jZG+Nui7SLATgjwY8g3VTqjyNw8rhCTx8mLP9XdT9zi/mTgFdFJtY+v2rujN3JdyVRxxHmcdNMXnUUJKHzCi6Vzl+aKSQrsGTShlWBImX2ddll0DN+iPKeTiCXIa2B0BLLkURqUg9rWG6bAG7k1mFoJldQKBgA370yBaAt3Df0tArY3NNp0HCbKvguOaMVZSQofuB4ZWM/fGJfyC57OHIl2y4+xDRlfP3rs6Vjg2vDsoznbT1iQB+3HxMOT1D6IunJK9qM30xsD2Jg8laZTSM6ZeVP3xIi9+M1fN4Jf02us3RBpYLCxTfk0TtZnX1Ydinwry3ok5AoGBAIzPwZTY29gLVrA7FOWtr+mKPASmhXWcotxDJyIKcWs8Rtg7EBqtx+3lKcAOOky44W1RXPheQ3127hvOe2s78s4TWDLgpNRCGakRpsR3XYV1MQpfudJ2TKwCeGm0eUvSDfpso1cZoeO1pO6NKkvCjTvrKZMS8JFl6Z8yTXwwJfW1AoGBAMZGHZ9iawLYqh9ho8JWSMlxvV+aQouoqLx5Ica0jfCQIT/fykqQa5QxD05WkBkK3bPapxFMifEm7+jGzKNDCcPRQwrUdJHpqPzuEsNux9s6LojKolCmEXeZS7f18dqK0YNGJeuPkCh4vlJze7iAhj6lb6UhcmkCtDkR+kMza4el");

            var privateKey = RSA.Create();
            privateKey.ImportPkcs8PrivateKey(privateKeyBytes, out _);

            var publicKey = Program.RemoveLineBreaks("-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1O2IB+zQH01J6MW+ZpyH/lENnr1ny9et\nGHi7H2xvo/l4yeJXIQg0H8rJfp59wxtEL0YnOzB9SFByNEwoDsd7D03PvLOhth6605Yp9Tk2mTxf\n9YFdXD+voWhjInvl+2X+Ny8OUctdOS1P/3GOBn4+AHBd6QCyMxRUljOx7khzTkWckPafk6Ft9k1W\nzkVso0ID+Yr553g4VOn8UBIYP/61x5GP/WlWvUnKnQw5x+gXEYEBW0uJ5zNqkh/AB851SWsWCoPz\nD2PiHKGrUygRVSzjZa1fJhP+fa/29SxWnH6IiEmrVXHyTYkZ4gVYTLX31cKv6yM9w4BcgCe2Gy65\nvyP63QIDAQAB-----END PUBLIC KEY-----");
            var decrypted = Program.Decrypt(json, privateKey, publicKey);

            Assert.Equal("""{"test":"test"}""", decrypted);
        }
    }
}