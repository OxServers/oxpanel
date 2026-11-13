#!/usr/bin/env bash
# Phase 60 (before reboot) — create state that must survive.
cd "$(dirname "$0")/.."; source phases/lib.sh
echo "== phase 60: reboot — preparing state"
check "create boota" bash -c "oxpanel-ctl tenant create boota --memory 256M --cpu-weight 40 --owner reboot | grep -q '^created=true'"
check "create bootb" bash -c "oxpanel-ctl tenant create bootb --memory 128M --owner reboot | grep -q '^created=true'"
check "site boota.test" bash -c "oxpanel-ctl vhost set boota.test --tenant boota --alias www.boota.test | grep -q '^changed=true'"
check "site bootb.test" bash -c "oxpanel-ctl vhost set bootb.test --tenant bootb --root www/site | grep -q '^changed=true'"
check "php site bootphp.test" bash -c "oxpanel-ctl vhost set bootphp.test --tenant bootb --root phpsite --php | grep -q '^changed=true'"
as_user bootb sh -c 'echo "<?php echo \"php-\" . (6*7);" > /home/bootb/phpsite/index.php'
eventually "bootphp.test serves" 30 0.2 http_body_is bootphp.test / php-42
check "node app site bootnode.test" bash -c "oxpanel-ctl vhost set bootnode.test --tenant boota --app node | grep -q '^changed=true'"
as_user boota sh -c "echo \"require('http').createServer((q, s) => s.end('node-42')).listen(process.env.PORT);\" > /home/boota/apps/bootnode.test/app.js"
check "restart node app" bash -c "oxpanel-ctl vhost restart-app bootnode.test | grep -q '^restarted=true'"
eventually "bootnode.test serves" 50 0.2 http_body_is bootnode.test / node-42
as_user boota sh -c 'echo boota > /home/boota/public_html/index.html'
as_user bootb sh -c 'echo bootb > /home/bootb/www/site/index.html'
eventually "boota.test serves" 30 0.2 http_body_is boota.test / boota
eventually "bootb.test serves" 30 0.2 http_body_is bootb.test / bootb
rm -f boot_sftp_key boot_sftp_key.pub; ssh-keygen -q -t ed25519 -N '' -f boot_sftp_key
check "SFTP key for boota" ctl_ok '^changed=true' oxpanel-ctl sftp add-key boota --key-file boot_sftp_key.pub
printf 'boot password stays put\n' > boot_sftp_pw; chmod 600 boot_sftp_pw
check "SFTP password for bootb" ctl_ok '^password=set' oxpanel-ctl sftp set-password bootb < boot_sftp_pw
if oxpanel-ctl host info | grep -q ' disk_quota=true '; then
  check "disk limit for bootb" ctl_ok '^changed=true' oxpanel-ctl tenant set-limits bootb --memory 128M --disk 64M
fi
if [ -x /usr/sbin/named ] && [ -x /usr/bin/dig ]; then
  # DNS hosting across a reboot: the sites above get zones as soon as it is
  # switched on; one is given a record and signed.
  cp -p /etc/oxpanel/daemon.env dns-daemon.env.bak
  printf '%s\n' OXPANEL_DNS=true OXPANEL_DNS_NAMESERVERS=ns1.boot.example,ns2.boot.example \
    OXPANEL_DNS_SOA_CONTACT=hostmaster@boot.example OXPANEL_DNS_IPV4=192.0.2.60 >> /etc/oxpanel/daemon.env
  systemctl restart oxpanel-daemon
  eventually "OxPanel's DNS server started" 60 0.5 systemctl -q is-active oxpanel-dns
  eventually "boota.test got a zone" 30 0.5 bash -c "oxpanel-ctl dns zone-list --tenant boota | grep -q '^zone=boota.test '"
  check "an MX record in it" ctl_ok '^changed=true' oxpanel-ctl dns record-add boota.test --tenant boota --name @ --type mx --priority 10 --value mx.boot.example
  check "DNSSEC on" ctl_ok '^zone=boota.test ' oxpanel-ctl dns dnssec boota.test on --tenant boota
  eventually "the zone is signed" 60 1 bash -c "oxpanel-ctl dns zone-show boota.test --tenant boota | grep -q ' dnssec=signed '"
  eventually "RRSIGs are served" 30 1 bash -c "dig +dnssec +norec @127.0.0.1 boota.test MX | grep -q 'RRSIG.*MX 13 '"
  oxpanel-ctl dns zone-show boota.test --tenant boota | sed -n 's/^ds=//p' > dns_ds.pre
  dig +short +norec @127.0.0.1 boota.test SOA | awk '{print $3}' > dns_serial.pre
  info "boota.test signed: $(cat dns_ds.pre), serial $(cat dns_serial.pre)"
else
  rm -f dns_serial.pre
fi
cat /proc/sys/kernel/random/boot_id > boot_id.pre
oxpanel-ctl tenant list > tenants.pre
oxpanel-ctl vhost list > vhosts.pre
getfacl -p /home/boota /home/boota/public_html > acl.pre 2>/dev/null
info "boot id $(cat boot_id.pre); rebooting"
phase_end
