# generate ca's key pair
keytool -genkeypair \
 -alias ca \
 -destalias ca \
 -dname 'CN=ca, OU=ca, O=ca, L=ca, S=ca, C=ca' \
 -keyalg rsa \
 -keypass password \
 -keysize 4096 \
 -keystore ca.jks \
 -sigalg sha512withrsa \
 -storepass password \
 -storetype jks \
 -v

# generate alice's key pair
keytool -genkeypair \
 -alias alice \
 -destalias alice \
 -dname 'CN=alice, OU=alice, O=alice, L=alice, S=alice, C=alice' \
 -keyalg rsa \
 -keypass password \
 -keysize 4096 \
 -keystore alice.jks \
 -sigalg sha512withrsa \
 -storepass password \
 -storetype jks \
 -v

# generate bob's key pair
keytool -genkeypair \
 -alias bob \
 -destalias bob \
 -dname 'CN=bob, OU=bob, O=bob, L=bob, S=bob, C=bob' \
 -keyalg rsa \
 -keypass password \
 -keysize 4096 \
 -keystore bob.jks \
 -sigalg sha512withrsa \
 -storepass password \
 -storetype jks \
 -v

# export ca's certification to file
keytool -exportcert \
 -alias ca \
 -file ca.pem \
 -keystore ca.jks \
 -rfc \
 -storepass password \
 -storetype jks \
 -v

# import ca's certification from file into alice's keystore
keytool -importcert \
 -alias ca \
 -file ca.pem \
 -keypass password \
 -keystore alice.jks \
 -noprompt \
 -rfc \
 -storepass password \
 -storetype jks \
 -v

# import ca's certificate from file into bob's keystore
keytool -importcert \
 -alias ca \
 -file ca.pem \
 -keypass password \
 -keystore bob.jks \
 -noprompt \
 -rfc \
 -storepass password \
 -storetype jks \
 -v

# generate certficate signing request for alice's public key to file
keytool -certreq \
 -alias alice \
 -file alice.csr \
 -keypass password \
 -keystore alice.jks \
 -storepass password \
 -storetype jks \
 -v

# generate certficate signing request for bob's public key to file
keytool -certreq \
 -alias bob \
 -file bob.csr \
 -keypass password \
 -keystore bob.jks \
 -storepass password \
 -storetype jks \
 -v

# sign alice's certificate signing request using the ca's private key and save it to file
keytool -gencert \
 -alias ca \
 -infile alice.csr \
 -keypass password \
 -keystore ca.jks \
 -outfile alice.pem \
 -rfc \
 -sigalg sha512withrsa \
 -storepass password \
 -storetype jks \
 -v

# sign bob's certificate signing request using the ca's private key and save it to file
keytool -gencert \
 -alias ca \
 -infile bob.csr \
 -keypass password \
 -keystore ca.jks \
 -outfile bob.pem \
 -rfc \
 -sigalg sha512withrsa \
 -storepass password \
 -storetype jks \
 -v

# import alice's signed certificate into her keystore
keytool -importcert \
 -alias alice \
 -file alice.pem \
 -keypass password \
 -keystore alice.jks \
 -rfc \
 -storepass password \
 -storetype jks \
 -v

# import bob's signed certificate into his keystore
keytool -importcert \
 -alias bob \
 -file bob.pem \
 -keypass password \
 -keystore bob.jks \
 -rfc \
 -storepass password \
 -storetype jks \
 -v

# import bob's signed certificate into alice's keystore
keytool -importcert \
 -alias bob \
 -file bob.pem \
 -keypass password \
 -keystore alice.jks \
 -rfc \
 -storepass password \
 -storetype jks \
 -v

# import alice's signed certificate into bob's keystore
keytool -importcert \
 -alias alice \
 -file alice.pem \
 -keypass password \
 -keystore bob.jks \
 -rfc \
 -storepass password \
 -storetype jks \
 -v
