using Xunit;
using System.Text.Json;
using System.Security.Cryptography;
using System.Text;
using Xunit.Abstractions;
using Serilog;

namespace DecryptTool.Tests
{
    public class DecryptToolTests
    {
        public ILogger _output;
        public DecryptToolTests(ITestOutputHelper output)
        {
            _output = output.CreateTestLogger();
        }
        public string GetFileHash(string filename)
        {
            var hash = new SHA1Managed();
            var clearBytes = File.ReadAllBytes(filename);
            var hashedBytes = hash.ComputeHash(clearBytes);
            return ConvertBytesToHex(hashedBytes);
        }

        public string ConvertBytesToHex(byte[] bytes)
        {
            var sb = new StringBuilder();

            for (var i = 0; i < bytes.Length; i++)
            {
                sb.Append(bytes[i].ToString("x"));
            }
            return sb.ToString();
        }

        [Fact()]
        public void DecryptTest()
        {
            var json = JsonSerializer.Deserialize<JsonElement>(File.ReadAllText($"files/answer_image_encrypted.json"));
            var privateKeyBytes = Convert.FromBase64String("MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCfmO39ggLnj9tGORmW9boM7WRbWy9t2MTgrsU6UrSq/c1EdxL3gh7bpZKM14CDikzcMSXydLM/9CpsJ3s5mGoywQYmtnRqzn1U7Ho+/IKVuROL8W5TGWc8y53CsohgQscRhMyq5uqvzUsbjnKWshfanNcFnm3Fqz6egGqRt0Ro77cDp72yA9yGTffimFNMpAgem04yajhXzrJU+cdekaZujfY9fqkbwFnSOWxSCEfR78HSzkMIjwvVxCzvQ5JAMM03h/uRBpBajhV+MdYuvQS+aUYb1dwSlzy5y6nf9abFPcd1m5SN220tnb/oqZsRwC3/Bx3HEUoXpwHR0eQE8+5tAgMBAAECggEAE1cvEBefTnyKcBofVcH1h/eEv+Vu+/rW8Pt8/zJino4fP/rGG6RzJN8NwW+kLUynP8/c72LhDhECyxSFxFcKF5h4rFxUA1V+rrnxnoxvLsG88qqRWhSsBBwQxDVqfW/aO+9B9jwBmMhiH7bFgCmY5m83R4EJgHjeH8skHwB8k9K39Db3+My5bFwYYR3VKC+4E6R6LeUmuZ7g5vTgR2YqYzRcJom8M0DCHeA+PDbf0hB3WrNUOEENgB6XxOTe5/ZrDdaSFDr7lx7xmKCw7RK7X9OZqtUtf83SFIX1JWvYNIbNktSOLgAMXnOKmYkywYbWhfPY9HjzkE26HfZYq0/DaQKBgQDOwGeMflk0ni7wZHHfEtG3m4ryhper2sxNjpMFx6F4mLbxR1742QLaW1YvykPzUYfzqMj2wRXK3ZbAESPUWo+V9Nq+P5jjFGC98tyfLizd3nKILs7f3brKZNLEYmkq6gWkmHqkRRywt/WngA1pRf8+5EokGJkTISAcNqHh+t9vVwKBgQDFnRarT359EMBNh569yFSouVPcdwuVGiEQMvi8KlxcuTE65EUeyllFfN8bYR18w3E8fqT0Ou0LjXscr9DXE65mHrdMki8VtTy5//HzD6jUFKqvyyeYUJqhD0gjNKsurUk3gVKsxNZiQOzZIaNXSuV8QzY1j7i+0d4sFD4Kn+Np2wKBgQC5+xfqqKmEDJs6wZAxU1N1b6TA31PGUs6fIZadh2N4AR/n0QTcoxHO7ISN/su7L+c0xuroFO6Oi2AVLBXn6wLoqNawdrMH6gfQNoxBYJ8ZggXS/RA5DtL9R07VO5VQ9izXUBZaeJUDXqfK4gSuYznlECSlbb8dFxo0ZuyeRDcDhwKBgQC9Rfe3f31kZo359EL7/YvwywliqXcjiZJPhLKu71fly882W/tEQYV9w9uhysPGgx/LVHXEI0h1/z4CvPcneYdZ8mOYaI/Gl/+hG19vcfk/oMfXdprnDZT9XLi4V7L6EymEi05XgnTgSNVSJyDe9DKXcXzTkmPeCP9mcsD1xiy4bwKBgHXo4FnnsXui6PSFLDXjnERcYyn/hYJg2I+FqibMoOe18wA0X18P9hKWQfRx+TsykdDRU0w8DLTn87j+8zVyAy/BeFK5f4IIo69J1zs0S7XXAHgKY9HYqL0KJ6bO3etqu9YT6jQEA2SM/VG4QElWMzDspoB4Gjm9cPC13NE9mojU");
            var privateKey = RSA.Create();
            privateKey.ImportPkcs8PrivateKey(privateKeyBytes, out _);

            var publicKey = Program.RemoveLineBreaks("-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn5jt/YIC54/bRjkZlvW6DO1kW1svbdjE4K7FOlK0qv3NRHcS94Ie26WSjNeAg4pM3DEl8nSzP/QqbCd7OZhqMsEGJrZ0as59VOx6PvyClbkTi/FuUxlnPMudwrKIYELHEYTMqubqr81LG45ylrIX2pzXBZ5txas+noBqkbdEaO+3A6e9sgPchk334phTTKQIHptOMmo4V86yVPnHXpGmbo32PX6pG8BZ0jlsUghH0e/B0s5DCI8L1cQs70OSQDDNN4f7kQaQWo4VfjHWLr0EvmlGG9XcEpc8ucup3/WmxT3HdZuUjdttLZ2/6KmbEcAt/wcdxxFKF6cB0dHkBPPubQIDAQAB-----END PUBLIC KEY-----");
            var decrypted = Program.Decrypt(json, privateKey, publicKey);

            Assert.Equal("""{"answers":[{"questionId":"ai_image_recognition","rawAnswer":{"confidence":0.010388672351837158,"img":"ZGF0YTppbWFnZS9wbmc7YmFzZTY0LGlWQk9SdzBLR2dvQUFBQU5TVWhFVWdBQUFBRUFBQUFCQ0FZQUFBQWZGY1NKQUFBQURVbEVRVlI0Mm1QOHovQy9IZ0FHZ3dKL2xLM1E2d0FBQUFCSlJVNUVya0pnZ2c9PQ=="}},{"questionId":"covapp_data_donation","rawAnswer":"yes"}],"version":1}""", decrypted);
        }

        [Theory]
        [InlineData("wrapped")]
        [InlineData("unwrapped")]
        public void DecodeImage(string type)
        {
            Program.DecodeImage(File.ReadAllText($"files/answer_image_{type}.json"), $"{type}");
            const string originalFile = @"files/image.png";
            string copiedFile = $"{type}.png";

            var originalHash = GetFileHash(originalFile);
            var copiedHash = GetFileHash(copiedFile);

            Assert.Equal(copiedHash, originalHash);
        }

    }
}