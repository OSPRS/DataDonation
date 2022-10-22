using DB;
using Microsoft.Extensions.DependencyInjection;
using System.Net.Http.Json;
using Xunit;
using Xunit.Abstractions;

namespace API.Tests;

public class ApiTests : IntegrationTestBase
{

  public ApiTests(IntegrationTestFactory<Program, DatabaseContext> factory, ITestOutputHelper output) : base(factory, output)
  {
  }

  [Fact()]
    public async Task GetAllArtWorks_WhenCalled_AlwaysReturnsAllArtWorks()
    {
        var client = Factory.CreateClient();

        // Arrange
        var response = await client.PostAsJsonAsync("/donate", """{"encryptedAnswers":"1C6oeBKm6/hjIRT+E2BYrQD+2+oD7op7iiCmyijPVg==","encryptedKey":"X2+sH9d+tQTHjdTGJ6X9vBewtgHIwwPQW46hb0dM3MtjJrj1jWrrb6LZDWgQkxlh485Rz6ica8Tg0YFWNHvNThbaufAbGJfFIGz38ZZXMm/9KnwTQJgbfL9ldCYfJi99Q9iCJFDlKETVDq9c0Xf7GxvbLHufREJ8PJYfZvCEjq04lPjXbHo8Hs9m2jijZSWBwbfjRpiWYu4i1cOimKBIJS0ZpgsT7mn2lZ+fQpE7RJKOML5I1KTlnm4KeO2S9u4mA7ysWPCy01GY1UFqkHYvy5wy/C/34IQilygSuA3VX+aTB8Zt9kLgBjp8otthB87CmXr77knNCiGv9FS6ObSyXQ==","iv":"rmLOHTCP4CnqqA26","signingKey":"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1O2IB+zQH01J6MW+ZpyH/lENnr1ny9et\nGHi7H2xvo/l4yeJXIQg0H8rJfp59wxtEL0YnOzB9SFByNEwoDsd7D03PvLOhth6605Yp9Tk2mTxf\n9YFdXD+voWhjInvl+2X+Ny8OUctdOS1P/3GOBn4+AHBd6QCyMxRUljOx7khzTkWckPafk6Ft9k1W\nzkVso0ID+Yr553g4VOn8UBIYP/61x5GP/WlWvUnKnQw5x+gXEYEBW0uJ5zNqkh/AB851SWsWCoPz\nD2PiHKGrUygRVSzjZa1fJhP+fa/29SxWnH6IiEmrVXHyTYkZ4gVYTLX31cKv6yM9w4BcgCe2Gy65\nvyP63QIDAQAB\n-----END PUBLIC KEY-----"}""");

        _output.Information(response.ReasonPhrase);
        // Assert
        Assert.NotNull(response);
        Assert.True(response.IsSuccessStatusCode, response.StatusCode.ToString());
    }
        
}