# Vanetza PKI Client

Our PKI client allows you to interact with any ETSI compliant C-ITS PKI provider.
Ideally, your PKI provider is listed in the European Certificate Trust List (ECTL).

In the examples below we use Eviden's L0 PKI (c-its-pki.eu). However, this tool is not limited to any particular PKI provider!


## Enrol at PKI included in ECTL

1. Fetch latest TLM from CPOC

`pki cpoc tlm fetch`

> Added TLM certificate "EU-TLM_L0" (8FFE810BDB0D71E6)

Writes ~/.local/share/vanetza/pki/certificates/8FFE810BDB0D71E6.tlm


2. Fetch ECTL from CPOC

`pki cpoc ectl fetch`

> Stored ECTL

Writes ~/.local/share/vanetza/pki/ectl.ctl and populates certificates/*.rca with Root CA certificaties listed in ECTL.


3. Select Root CA for your station

`pki station set-root-ca 1B5CB4BEBE6FE9E9`

> Found Root CA certificate in cache.


4. Fetch CTL from Distribution Centre (DC) of your Root CA

`pki dc info`

> DC URL: https://0.eu-dc.l0.c-its-pki.eu/

Prints the DC URL as found in the ECTL for the previously selected Root CA.

`pki dc getctl --print`

> - EA: http://0.eu-ea.l0.c-its-pki.eu/ [AA] \
> - AA: http://0.eu-aa.l0.c-its-pki.eu/ \
> Fetched CTL matches Root CA digest \
> CTL is valid. Added to local trust list storage.

Writes ~/.local/share/vanetza/pki/ctls/1B5CB4BEBE6FE9E9.ctl


5. Perform initial enrolment at EA

Initial enrolment needs a canonical (bootstrap) key pair.
In a real deployment this key is provisioned by the station manufacturer.
For testing you can generate one:

`pki key generate --out ~/station_key.pem`

> Wrote /home/user/station_key.pem \
> Key type: BrainpoolP256r1 \
> Canonical public key: 021234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF

Use `--key-type` to pick a curve (`BrainpoolP256r1` (default), `NistP256`, `BrainpoolP384r1`) and `--force` to overwrite an existing file.

`pki enrol init --canonical-id station_name --canonical-keyfile ~/station_key.pem`

> Root CA 1B5CB4BEBE6FE9E9 \
> Canonical identifier: station_name \
> Canonical public key X=1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF \
> Enroling against EA certificate: D07F4E6D4D1DFA70 \
> Enroling at EA URL: http://0.eu-ea.l0.c-its-pki.eu/ \
> Stored new EC with HashedId8 = 1234567890ABCDEF \
> Station can sign with received EC


6. Check your station's state

`pki station`

> Canonical identifier: station_name \
> Enrolled: yes \
> EC digest: 1234567890ABCDEF \
> EC certificate: [available] \
> Root CA: 1B5CB4BEBE6FE9E9 \
> DC URL: https://0.eu-dc.l0.c-its-pki.eu/


## Fetch Authorization Tickets (ATs) from PKI's AA

Your station needs to be enrolled with valid EC certificate before you can retrieve ATs.

The following command fetches a single AT with default settings.
The command line option `--permission` is required at least once to determine the requested AT application permissions.
However, it is more convenient to set these permissions in the local configuration file (`~/.config/vanetza/pki.cfg`):

```
[authorization.request]
permission = ["36:01FFFC", "37:01FFFFFF", "141"]
```

`pki at request`

> Authorizing against AA AF65A276F2D4EBC9 at http://0.eu-aa.l0.c-its-pki.eu/ \
> Stored new AT ABCDEF1234567890 \
> ABCDEF1234567890 [valid now] \
>  valid: 2026-06-06 07:06:29 until 2026-06-13 07:06:29 \
>  permissions: 36:01FFFC 37:01FFFFFF 141
