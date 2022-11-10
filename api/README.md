# Datadonation - API

## Development

[Install .NET Core SDK or Runtime](https://dotnet.microsoft.com/download/dotnet/6.0)

Run `docker-compose up -d` before to start the local database.

```
dotnet restore
dotnet watch run
```


## Production

### Preparation

1. [Install .NET Core SDK or Runtime](https://dotnet.microsoft.com/download/dotnet/5.0)
2. Install MySQL `apt-get install mysql`


### Installation



Change the [appsettings.json](./appsettings.json) accordingly. (e.g. The Database Connection String)

```bash
# Add user to mysql: https://www.digitalocean.com/community/tutorials/how-to-create-a-new-user-and-grant-permissions-in-mysql
mysql 
  CREATE USER 'datadonation'@'localhost' IDENTIFIED BY 'YourPassword123';
  GRANT ALL PRIVILEGES ON * . * TO 'newuser'@'localhost';
  FLUSH PRIVILEGES;
    
# Install this service
git clone https://github.com/CovOpen/DataDonation.git
cd ./DataDonation/api
dotnet restore
dotnet publish -c Release -o ./app
# Edit the appsettings.json file in ./app/appsettings.json and change the connection string to the just created user and database. 
nano ./app/appsettings.json
# Test the startup
dotnet ./app/DataDonation.dll
```

Add it to your reverse proxy, e.g. Nginx: 
```bash
  location / {
    proxy_pass http://127.0.0.1:8000;
  }
```


Add it as system service: 
```bash
cat > /etc/system/sytemd/data-donation.service <<EOF
[Unit]
Description=Data Donation
# Starts this service as soon as it is connected with the internet
After=network.target auditd.service

[Service]
ExecStart=/usr/bin/dotnet /home/path/to/DataDonation/app/DataDonation.dll
KillMode=process
Restart=on-failure
RestartPreventExitStatus=255
WorkingDirectory=/home/path/to/DataDonation/app

[Install]
WantedBy=multi-user.target
EOF

# Enable the service to restart
systemctl daemon-reload
systemctl enable data-donation.service
systemctl start data-donation.service
systemctl status data-donation.service

# Does not run? Find the whole error message with:
journalctl -u data-donation.service
```
