setup() {
    rm -r decrypted || echo 0
    rm -r keys || echo 0
    rm decrypt-tool || echo 0
    cd ../decrypt-tool
    dotnet publish --runtime linux-x64 --configuration Release -p:PublishSingleFile=true -p:PublishTrimmed=true --self-contained true -o ./../tests-bats
    cd ../tests-bats
    rm DB.pdb
    rm decrypt-tool.pdb
    mkdir keys || echo 0
    openssl rsa -in example.pem -outform PEM -pubout -out keys/public_key.pem -passin pass:example
    openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in example.pem -out keys/private_key.pem -passin pass:example

# Setup Database
    cd ..
    docker compose up -d
    until [ "`docker inspect -f {{.State.Health.Status}} datadonation-db-1`" == "healthy" ]; do
        docker inspect -f {{.State.Health.Status}} datadonation-db-1
        sleep 1;
    done;
    echo "Ready!"
    sleep 1
    docker compose exec -T db mysql -uroot -pexample <<EOF
CREATE DATABASE datadonation;
USE datadonation;
$(cat ./tests-bats/backup.sql)
EOF
    cd tests-bats
}

@test "decrypting" {

    export DECRYPT_TOOL_CONNECTION_STRING="server=localhost;database=datadonation;user=root;password=example;OldGuids=true"
    run ./decrypt-tool --privateKeyFolder keys
    [ "$status" -eq 0 ]
    echo "$output"

    FILE="./decrypted"
    [ ! -d "$FILE" ] && echo "Directory $FILE does not exists." && exit 1
    FILE="./decrypted/cleartext_data.csv"
    if [ ! -f "$FILE" ]; then
        echo "$FILE does not exist."
        exit 1
    fi

    FILE="./decrypted/cleartext_data.csv"
    if [ -f "$FILE" ]; then
        cmp --silent ./../tests/files/image.png ./decrypted/bdbfef22-bfef-efbd-bfbd-efbfbdefbfbd.png || echo "Files are different!" || exit 1
    else
        echo "$FILE does not exist."
        exit 1
    fi
    # [ "$output" = "hello world" ]
}


@test "generategif" {
    mkdir ./demo || echo 0
    cp ./decrypt-tool ./demo/decrypt-tool
    cp -r keys ./demo/keys
    cd demo

    vhs ../demo.tape

    mv demo.gif ../../docs/demo.gif

    cd ..
    rm -r demo
}


teardown() {
    # rm -r ./decrypted
    cd ..
    docker-compose down

}
