# Decrypt-Tool

Tool to decrypt the database and export the data locally.

## Usage

To use the `decrypt-tool` you have to supply a ConnectionString to the encrypted Database and be in possession of the right private and public key. Place the keys in the `keys` folder as following:

```
decrypt-tool.exe
decrypt-tool
keys
 |-- private_key.pem
 |-- public_key.pem
```

![GIF of the CLI Usage](../docs/demo.gif)

The Keys have to be in PKCS8 Format in order to work.

### Executables

1. Go to the last build and download the executables.
2. Set Environment Variable `DECRYPT_TOOL_CONNECTION_STRING`.
3. Run `decrypt-tool` or `decrypt-tool.exe` on from commandline, on you respective platform.
4. Follow the instructions.

### From source

> [Install .NET Core SDK or Runtime before](https://dotnet.microsoft.com/download/dotnet/6.0)

1. Clone this repository.
2. Run `cd decrypt-tool && dotnet run`
