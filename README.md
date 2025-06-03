# Cloud HSM

## Build
Download the CloudHSM JCE provider from the AWS console and place it in the `jce` directory.

## Setup
Assuming CloudHSM is behind a bastion then ssh port forwarding is required to access the CloudHSM cluster.

```bash
ssh -i hsm.pem -N  -L 2223:<cluster hostname>:2223 ec2-user@<bastion ip>
```