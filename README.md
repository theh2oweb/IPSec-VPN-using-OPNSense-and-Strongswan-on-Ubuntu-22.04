# IPSec VPN using OPNSense and Strongswan (on Ubuntu 22.04)

## Mobile client / Roadwarrior example
Reference: [Strongswan VPN - Roadwarrior case with Virtual IP](https://docs.strongswan.org/docs/5.9/config/quickstart.html#_roadwarrior_case_with_virtual_ip)

The main objective is to allow a mobile user/client (aka RoadWarrior) to remotely access ressource on a secured private network.  
In this example, the user is using a laptop connected to Internet.  
```text
  TARGET NETWORK           VPN GATEWAY                            VPN PEER          VIRTUAL IP

ttt.ttt.ttt.ttt/tt --|-- ggg.ggg.ggg.ggg > ==[ INTERNET ]== < ppp.ppp.ppp.ppp ( vvv.vvv.vvv.vvv/vv )

                         [================== IPSec Tunnel ==================]
[<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< Secured communication >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>]
                         [================== IPSec Tunnel ==================]
```
The generic process is:
1. User connects his laptop, the `VPN peer`, to his local network in order to obtain Internet access.
2. `VPN peer` instanciates an `IPSec Tunnel` with the `VPN gateway`.  
    2.1. `ppp.ppp.ppp.ppp` establishes an `IPSec Tunnel` with `ggg.ggg.ggg.ggg`.  
    2.2. `VPN peer` creates a `Virtual IP vvv.vvv.vvv.vvv/vv`, to be used in the `IPSec Tunnel` to communicate with the `Target network`.  
    2.3. `VPN peer` adds a route for the `Target network ttt.ttt.ttt.ttt/tt` pointing to its `Virtual IP vvv.vvv.vvv.vvv/vv`.  
3. The `VPN peer` can access the `Target network` to send and retrieve datas.  

## VPN Gateway
`Current version of OPNSense is 23.7.2` _(September 17th, 2023)_  

In this section, we will:
1. Create a CA authority on the `VPN gateway`  
    1.1. Create a certificate for the `VPN gateway`  
    1.2. Create a certificate for the `VPN peer`  
2. Create a `VPN Tunnel` configuration  
    2.1. Configure `VPN gateway`'s IPSec Phase 1  
    2.2. Configure `VPN gateway`'s IPSec Phase 2  
3. Start the VPN Tunnel listener  

### Create a Certificate Authority (CA) on the VPN gateway (OPNSense)
* Go to __System > Trust > Authorities__.
* Click the __Add__ button.

Enter the following values:
```text
Descriptive name:                   <Enter your value>

Internal certificate authority
Method:                             Create an internal certificate authority
Key Type:                           RSA
Key length:                         2048
Digest algorithm:                   SHA256
Lifetime:                           <Enter your value>

Distinguished Name
Country code:                       <Select your value>
State or Province:                  <Enter your value>
City:                               <Enter your value>
Organization:                       <Enter your value>
Email address:                      <Enter your value>
Common Name:                        <Enter your value>
```

### Create a certificate for the VPN Gateway
* Go to __System > Trust > Certificates__.  
* Click the __Add__ button.  

Enter/select the following values:
```text
Method:                                                             Create an internal Certificate
Descriptive name:                                                   <Enter your value>

Internal Certificate
Certificate authority:                                              <Select previously created CA certificate>
Type:                                                               Server Certificate
Key Type:                                                           RSA
Key length (bits):                                                  2048
Digest Algorithm:                                                   SHA256
Lifetime (days):                                                    <Enter your value>
Private key location:                                               Save on this firewall

Distinguished name
Country Code:                                                       <Enter your value>
State or Province:                                                  <Enter your value>
City:                                                               <Enter your value>
Organization:                                                       <Enter your value>
Email Address:                                                      <Enter your value>
Common Name:                                                        <Enter your value>

Alternative Names
DNS                                                                 <Enter your value, ex: vpn.gateway.tld>
IP                                                                  <Enter your value, ex: ggg.ggg.ggg.ggg>
```
* Click __Save__ button.

### Configure VPN Gateway's IPSec Phase 1
* Go to __VPN > IPSec > Mobile clients__  

Enter/select the following values:
```text
Extended Authentication (Xauth)
Backend for authentication:                                         Local Database
Enforce local group:                                                (none)

Radius (eap-radius)
Backend for authentication:                                         Nothing selected

IKE Extensions
Enable IPSec Mobile Clients Support:                                <check the box>

Client Configuration (mode-cfg)
Provide a Virtual IPv4 address to clients:                          <check the box>
                                                                    <Enter your value, ex: vvv.vvv.vvv.vvv/vv>
Provide a Virtual IPv6 address to clients:                          <leave the box unchecked>
Provide a list of accessible networks to clients:                   <leave the box unchecked>
Allow clients to save Xauth passwords (Cisco VPN client only):      <leave the box unchecked>
Provide a default domain name to clients:                           <leave the box unchecked>
Provide a list of split DNS domain names to clients:                <leave the box unchecked>
Provide a DNS server list to clients:                               <leave the box unchecked>
Provide a WINS server list to clients:                              <leave the box unchecked>
Phase 2 PFS Group:                                                  14 (2048 bits)
Provide a login banner to clients                                   <leave the box unchecked>
```
* Click __Save__ button.  
* Click __Create Phase 1__ button.  

Enter/select the following values:
```text
General information
Disable this phase1 entry:                                          <leave the box unchecked>
Connection method:                                                  Respond only
Key Exchange version:                                               V2
Internet Protocol:                                                  IPv4
Interface:                                                          <select your value>
Description:                                                        <enter your value>

Phase 1 proposal (Authentication)
Authentication method:                                              Mutual RSA (Seems to be inverted with Mutual Public Key)
My identifier:                                                      Automatic
                                                                    <leave empty>
My Certificate:                                                     <select previously created certificate>
Remote Certificate Authority:                                       <select previously created CA certificate>

Phase 1 proposal (Algorithms)
Encryption algorithm:                                               AES
                                                                    256
Hash algorithm:                                                     SHA256
DH key group:                                                       14 (2048 bits)

Advanced Options
Install policy:                                                     <check the box>
Disable Rekey:                                                      <leave the box unchecked>
Disable Reauth:                                                     <leave the box unchecked>
Tunnel Isolation:                                                   <leave the box unchecked>
SHA256 96 Bit Truncation:                                           <leave the box unchecked>
NAT Traversal:                                                      Enable
Disable MOBIKE:                                                     <leave the box unchecked>
Close Action:                                                       None
Unique:                                                             Replace
Dead Peer Detection:                                                <leave the box unchecked>
Inactivity timeout:                                                 <leave empty>
Keyingtries:                                                        <leave empty>
Lifetime:                                                           <leave empty>
Margintime                                                          <leave empty>
Rekeyfuzz:                                                          <leave empty>
```

### Configure VPN Gateway's IPSec Phase 2
* Go to __VPN > IPSec > Tunnel Settings [legacy]  
* Click on the __Add__ button next to the created Phase 1  

Enter/select the following values:
```text
General information
Disabled:                                                           <leave the box unchecked>
Mode:                                                               Tunnel IPv4
Description:                                                        

Local Network
Type:                                                               Network
Address:                                                            <enter your value, ex: ttt.ttt.ttt.ttt/tt>

Phase 2 proposal (SA/Key Exchange)
Protocol:                                                           ESP
Encryption algorithms:                                              AES256
Hash algorithms:                                                    SHA256
PFS key group:                                                      <leave empty, defaults to Mobile client configuration>
Lifetime:                                                           3600

Advanced Options
Automatically ping host:                                            <leave empty>
```
* Click __Save__ button.  
* Go to __VPN > IPSec > Tunnel Settings [legacy]  
* Check the __Enable IPSec__ checkbox.  
* Click on the __Apply changes__ button.  

### Configure firewall rules
To accept IPSec connection and allow tunnel communication.  
* Go to __Firewall > Rules > \<your interface\> >  
* Click on the __Add__ button.  
* Create the 3 followings rules
```text
Protocol	Source	                Port	Destination	            Port	            Gateway	    Schedule	Description
IPv4 ESP	*	                    *	    ggg.ggg.ggg.ggg/gg	    *	                *	        *		    Allow IPSec ESP
IPv4 UDP	*	                    *	    ggg.ggg.ggg.ggg/gg	    500 (ISAKMP)	    *	        *		    Allow IPSec ISAKMP
IPv4 UDP	*	                    *	    ggg.ggg.ggg.ggg/gg	    4500 (IPsec NAT-T)	*	        *		    Allow IPSec NAT-T
IPv4 *	        vvv.vvv.vvv.vvv/vv	    *	    ttt.ttt.ttt.ttt/tt	    *	                *	        *		    Allow Secured communication
```
__`TO BE COMPLETED`__

## VPN Peer
`Current version of Strongswan is 5.9.5` _(September 17th, 2023)_  

In this section, we will:
1. Install the following tools
    1.1. The `strongswan service` that will manage the `IPSec Tunnel`.  
    1.2. The `swanctl command line tool` to allow user and/or script interaction with the `strongswan service`. 
2. Configure the `IPSec Tunnel` connection.
3. Establish a VPN connection.

### Strongswan packages installation
```shell
apt install charon-systemd strongswan-swanctl
```
Each package will also install the following dependancies:  
* __charon-systemd__ 
    * charon-systemd (strongSwan IPsec client, systemd support)
    * libcharon-extauth-plugins (strongSwan charon library (extended authentication plugins))
    * strongswan-libcharon (strongSwan charon library)

* __strongswan-swanctl__
    * libstrongswan (strongSwan utility and crypto library)
    * libstrongswan-standard-plugins (strongSwan utility and crypto library (standard plugins))
    * strongswan-swanctl (strongSwan IPsec client, swanctl command)

### Strongswan authentication configuration
Copy the provided certificates to the following directories.
```text
/etc/swanctl/x509ca/<peer>-CA.crt
/etc/swanctl/x509/<peer>.crt
/etc/swanctl/private/<peer>.key
```  
### Strongswan tunnel configuration
Create a `swanctl` configuration file in __/etc/swanctl/conf.d/\<peer\>.conf__
```ini
connections{
	cacert = <peer>-CA.crt
	tunnel-<peer>-ipsec {
		version = 2
		proposals = aes256-sha2_256-modp2048
		remote_addrs = <ggg.ggg.ggg.ggg>
		vips = 0.0.0.0
		local {
			auth = pubkey
			certs = <peer>.crt
		}
		remote {
			auth = pubkey
		}
		children {
			<peer>-ipsec {
				mode = tunnel
				esp_proposals = aes256-sha256-modp2048
				# https://docs.strongswan.org/docs/5.9/swanctl/swanctlConf.html#_connections_conn_children
				local_ts = dynamic
				remote_ts = 0.0.0.0/0
				start_action = start
				close_action = start
				dpd_action = restart
				updown = /sbin/tunnel_updown.sh
			}
		}
	}
}
```

### Strongswan client usage
To restart the service, execute the following command.
```shell
systemctl stop strongswan && systemctl start strongswan
```

## Other useful things :-)

### __P12 certificate conversion__
Even if `strongswan` can use a P12 certificate, it's normally secured by a password.  
You can use the following script to extract the CA, cert and key from the P12 certificate.  

__`NB: It is insecure to leave the certificate key without a password. Another solution may exists with strongswan.`__
```bash
#!/bin/bash

P12=<certificate>.p12
OUTPUT=<peer>
LEGACY="-legacy"
# https://www.openssl.org/docs/man3.0/man1/openssl-pkcs12.html
# -legacy
    # In the legacy mode, the default algorithm for certificate encryption is RC2_CBC or
    # 3DES_CBC depending on whether the RC2 cipher is enabled in the build. The default 
    # algorithm for private key encryption is 3DES_CBC. If the legacy option is not specified, 
    # then the legacy provider is not loaded and the default encryption algorithm for both 
    # certificates and private keys is AES_256_CBC with PBKDF2 for key derivation.

read -sp "Enter P12 file password: " PASSWORD

echo ""
echo "### Extract private key ###"
openssl pkcs12 -in ${P12} -nocerts -out ${OUTPUT}.key ${LEGACY} -noenc -password pass:${PASSWORD}

echo ""
echo "### Extract certificates ###"
openssl pkcs12 -in ${P12} -clcerts -nokeys -out ${OUTPUT}.crt ${LEGACY} -password pass:${PASSWORD}

echo ""
echo "### Extract CA certificate ###"
openssl pkcs12 -in ${P12} -cacerts -nokeys ${LEGACY} -password pass:${PASSWORD} | openssl x509 -out ${OUTPUT}-CA.crt

echo ""
echo "### Check RSA key ###"
openssl rsa -check -noout -in ${OUTPUT}.key

echo ""
echo "### Verify private key matches certificate ###"
CERT=$(openssl x509 -noout -modulus -in ${OUTPUT}.crt | openssl md5)
KEY=$(openssl rsa -noout -modulus -in ${OUTPUT}.key | openssl md5)
if [[ $CERT == $KEY ]]; then
    echo "OK, ${OUTPUT}.key matches ${OUTPUT}.crt"
else
    echo "ERROR, ${OUTPUT}.key DOES NOT matches ${OUTPUT}.crt"
fi

echo ""
echo "### Verify certificate matches authority ###"
openssl verify -CAfile ${OUTPUT}-CA.crt ${OUTPUT}.crt

echo ""
```

### __Strongswan updown.sh script__
In case the strongswan configuration specifies an `updown` parameter in the `children` section, you can create the following script in `/sbin/tunnel_updown.sh`  
__NB__: The following script mainly adds and removes routes towards the `Target network` via the `Virtual IP` on the `VPN peer`. You can elaborate on this !
```bash
#!/bin/bash

LOGFILE=/var/log/<peer>_updown.log

log_env () {
    echo "" >> ${LOGFILE} 2>&1
    echo "### LOGGING ENVIRONMENT ###" >> ${LOGFILE} 2>&1
    env >> ${LOGFILE} 2>&1
    # PLUTO_PEER_ID=C=xx, ST=xx, L=xx, O=xx, E=xxx@yyy.tld, CN=xxx
    # PLUTO_ME=ppp.ppp.ppp.ppp (private IP)
    # PLUTO_PEER_CLIENT=ttt.ttt.ttt.ttt/tt
    # PWD=/
    # PLUTO_VERSION=1.1
    # PLUTO_REQID=1
    # PLUTO_MY_PORT=0
    # PLUTO_MY_PROTOCOL=0
    # PLUTO_PEER_PORT=0
    # PLUTO_MY_SOURCEIP4_1=vvv.vvv.vvv.vvv
    # PLUTO_CONNECTION=<peer>-ipsec
    # PLUTO_PEER_PROTOCOL=0
    # SHLVL=1
    # PLUTO_MY_CLIENT=vvv.vvv.vvv.vvv/vv
    # PLUTO_MY_ID=C=xx, ST=xx, L=xx, O=xx, E=xxx@yyy.tld, CN=xxx
    # PLUTO_PEER=ggg.ggg.ggg.ggg
    # PLUTO_VERB=up-client
    # PLUTO_INTERFACE=ens160
    # PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
    # PLUTO_UNIQUEID=1
    # PLUTO_MY_SOURCEIP=vvv.vvv.vvv.vvv
    # PLUTO_PROTO=esp
    # _=/usr/bin/env
}

log_journalctl () {
    echo "" >> ${LOGFILE} 2>&1
    echo "### LOGGING STRONGSWAN JOURNALCTL ###" >> ${LOGFILE} 2>&1
    journalctl -eu strongswan --since "2 minutes ago" >> ${LOGFILE} 2>&1
}

log_sas () {
    echo "" >> ${LOGFILE} 2>&1
    echo "### LOGGING SECURITY ASSOCIATIONS ###" >> ${LOGFILE} 2>&1
    # swanctl --list-sas >> ${LOGFILE} 2>&1
}

add_routes() {
    echo "" >> ${LOGFILE} 2>&1
    echo "### ADDING ROUTES ###" >> ${LOGFILE} 2>&1
    ip route add ${PLUTO_PEER_CLIENT} via ${PLUTO_MY_SOURCEIP4_1}
}

del_routes() {
    echo "" >> ${LOGFILE} 2>&1
    echo "### DELETING ROUTES ###" >> ${LOGFILE} 2>&1
    ip route del ${PLUTO_PEER_CLIENT} via ${PLUTO_MY_SOURCEIP4_1}
}

restart_tunnel () {
    echo "" >> ${LOGFILE} 2>&1
    echo "### RESTARTING TUNNEL ###" >> ${LOGFILE} 2>&1
    # swanctl --terminate --force --child ${PLUTO_CONNECTION}
    # swanctl --reload-settings >> ${LOGFILE} 2>&1
    # swanctl --load-all --noprompt >> ${LOGFILE} 2>&1
    # echo "" >> ${LOGFILE} 2>&1
    # swanctl --initiate --child ${PLUTO_CONNECTION} >> ${LOGFILE} 2>&1
}

echo -e "\n###" $(date +"%Y-%m-%d %H:%M:%S") "BEGIN OF ${0} for ${PLUTO_VERB} ###\n" >> ${LOGFILE} 2>&1
echo "" >> ${LOGFILE} 2>&1

log_env

case ${PLUTO_VERB} in
    up-client)
        add_routes
        log_sas
        ;;
    down-client)
        del_routes
        restart_tunnel
        ;;
    *)
        echo "" >> ${LOGFILE} 2>&1
        echo "!!! UNMANAGED PLUTO_VERB '${PLUTO_VERB}' !!!" >> ${LOGFILE} 2>&1
        ;;
esac

echo "" >> ${LOGFILE} 2>&1
echo -e "\n###" $(date +"%Y-%m-%d %H:%M:%S") "END OF ${0} for ${PLUTO_VERB} ###\n" >> ${LOGFILE} 2>&1
```

### Strongswan IPSec tunnel monitoring
```shell
watch -d "swanctl --list-sas"
```
Outputs
```text
tunnel-<peer>-ipsec: #44, ESTABLISHED, IKEv2, 6bf4f4e18f79736a_i* 64145eb8c6e62a46_r
  local  'C=xx, ST=xx, L=xx, O=xx, E=xxx@yyy.tld, CN=xxx' @ ppp.ppp.ppp.ppp[4500] [vvv.vvv.vvv.vvv]
  remote 'C=xx, ST=xx, L=xx, O=xx, E=xxx@yyy.tld, CN=xxx' @ ggg.ggg.ggg.ggg[4500]
  AES_CBC-256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_2048
  established 11373s ago, rekeying in 2796s
  <peer>-ipsec: #57, reqid 1, INSTALLED, TUNNEL, ESP:AES_CBC-256/HMAC_SHA2_256_128/MODP_2048
    installed 1990s ago, rekeying in 1517s, expires in 1970s
    in  c8259053,      0 bytes,     0 packets
    out c7d90dda,      0 bytes,     0 packets
    local  10.3.0.1/32
    remote 192.168.2.0/24
```
