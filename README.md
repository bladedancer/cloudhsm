# Cloud HSM

## Build
Download the CloudHSM JCE provider from the AWS console and place it in the `jce` directory.

## Setup
Assuming CloudHSM is behind a bastion then ssh port forwarding is required to access the CloudHSM cluster.

```bash
ssh -i hsm.pem -N  -L 2223:<cluster hostname>:2223 ec2-user@<bastion ip>
```

### Insall the JCE Provider

Register the JCE Provider, see: https://docs.aws.amazon.com/cloudhsm/latest/userguide/keystore-prerequisites_5.html
e.g.
```
security.provider.13=com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider
```

## Create local client certificates

If you need to test without cloud hsm:

```
    openssl req -x509 -newkey rsa:4096 -keyout clikey.pem -out clicert.pem -sha256 -days 3650 -nodes -subj "/C=IE/ST=Dublin/L=Dublin/O=CompanyName/OU=CompanySectionName/CN=mtls.example.com"
```

## Create HSM client certificates
[ProviderService.java](src/main/java/com/matthews/poc/cloudhsm/api/ProviderService.java)
Install OpenSSL dynamic libraries for CloudHSM, see: https://docs.aws.amazon.com/cloudhsm/latest/userguide/openssl5-install.html
Install: https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-library-install.html

### Create a new key pair with OpenSSL

```bash
openssl genrsa -engine cloudhsm -out demo.pem 2048
openssl req -engine cloudhsm -new -key demo.pem -out demo.csr -sha256 -subj "/CN=demo.example.com/O=Demo/C=IE"
openssl x509 -engine cloudhsm -req -days 365 -in demo.csr -signkey demo.pem -out demo.crt -sha256
```

The problem with this approach is that I can't set a label...


```bash
export CLOUDHSM_PIN=<CU user name>:<password>

aws-cloudhsm > key generate-asymmetric-pair rsa --public-label example --private-label example-key --public-attributes verify=true --private-attributes sign=true
 --modulus-size-bits 2048 --public-exponent 65537
aws-cloudhsm > key generate-file --encoding reference-pem --path example.key --filter attr.label=example-key
openssl req -engine cloudhsm -new -key example.key -out example.csr
openssl x509 -engine cloudhsm -req -days 365 -in example.csr -signkey example.key -out example.crt
````

Note it's possible to use the public key from AWS but that requires using the PKCS11 engine and I didn't bother.