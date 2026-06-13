/**
 * IPSec / IKEv2 (strongSwan) configuration builders for HomeShield's
 * client-to-site remote-access VPN, plus the Windows client provisioning
 * script. Pure string builders — unit tested in ipsec.test.mjs.
 *
 * Auth model: IKEv2 with EAP-MSCHAPv2 (username/password). The server
 * authenticates with a certificate (from an internal CA the agent generates);
 * clients trust that CA and log in with credentials.
 */

const CONN = 'homeshield-ikev2';
const POOL = 'homeshield-pool';

/**
 * Builds swanctl.conf for a strongSwan IKEv2 EAP remote-access server.
 * @param cfg { endpoint, poolSubnet, dns, localSubnets }
 *   endpoint     server identity (FQDN or IP, must match the server cert SAN)
 *   poolSubnet   virtual IP pool handed to clients, e.g. "10.9.0.0/24"
 *   dns          DNS server pushed to clients
 *   localSubnets traffic selector(s) routed into the tunnel ("0.0.0.0/0" = full)
 */
export function buildSwanctlConf(cfg) {
  const endpoint = cfg.endpoint || '';
  const pool = cfg.poolSubnet || '10.9.0.0/24';
  const dns = cfg.dns || '1.1.1.1';
  const localTs = (cfg.localSubnets && cfg.localSubnets.trim()) || '0.0.0.0/0';

  return [
    '# HomeShield NGFW - strongSwan IKEv2 EAP (managed)',
    'connections {',
    `   ${CONN} {`,
    '      version = 2',
    `      pools = ${POOL}`,
    '      local_addrs = %any',
    '      proposals = aes256-sha256-modp2048,aes256-sha1-modp1024,default',
    '      encap = yes',
    '      dpd_delay = 30s',
    '      fragmentation = yes',
    '      send_cert = always',
    '      local {',
    '         auth = pubkey',
    '         certs = homeshield-server.pem',
    `         id = ${endpoint}`,
    '      }',
    '      remote {',
    '         auth = eap-mschapv2',
    '         eap_id = %any',
    '      }',
    '      children {',
    `         ${CONN}-net {`,
    `            local_ts = ${localTs}`,
    '            rekey_time = 0',
    '            dpd_action = clear',
    '            esp_proposals = aes256-sha256,aes256-sha1,default',
    '         }',
    '      }',
    '   }',
    '}',
    'pools {',
    `   ${POOL} {`,
    `      addrs = ${pool}`,
    `      dns = ${dns}`,
    '   }',
    '}',
    '',
  ].join('\n');
}

/** Builds the swanctl secrets section with EAP credentials for each user. */
export function buildSwanctlSecrets(users = []) {
  const lines = ['secrets {'];
  let i = 0;
  for (const u of users) {
    if (!u.username || u.password == null) continue;
    i++;
    lines.push(
      `   eap-${i} {`,
      `      id = ${u.username}`,
      `      secret = "${String(u.password).replace(/"/g, '')}"`,
      '   }',
    );
  }
  lines.push('}', '');
  return lines.join('\n');
}

/**
 * Builds the nftables table that allows IKE/ESP in and masquerades the VPN
 * pool out, so IPSec clients can connect and reach the network. Separate
 * self-healing table at priority -5 (like the WireGuard NAT table).
 */
export function buildIpsecNatTable(poolSubnet = '10.9.0.0/24') {
  return [
    '#!/usr/sbin/nft -f',
    '# HomeShield NGFW - IPSec/IKEv2 firewall + NAT',
    'table inet homeshield_ipsec',
    'delete table inet homeshield_ipsec',
    '',
    'table inet homeshield_ipsec {',
    '  chain input {',
    '    type filter hook input priority -5; policy accept;',
    '    udp dport { 500, 4500 } counter accept',
    '    meta l4proto esp counter accept',
    '  }',
    '  chain postrouting {',
    '    type nat hook postrouting priority 100; policy accept;',
    `    ip saddr ${poolSubnet} counter masquerade`,
    '  }',
    '}',
    '',
  ].join('\n');
}

/**
 * Builds a PowerShell installer that provisions the Windows built-in IKEv2
 * client: imports the CA, creates the VPN connection (EAP-MSCHAPv2), and sets
 * split/full tunneling.
 *
 * @param cfg { name, endpoint, caCertPem, fullTunnel }
 */
export function buildWindowsInstaller(cfg) {
  const name = (cfg.name || 'HomeShield VPN').replace(/[`"$]/g, '');
  const endpoint = (cfg.endpoint || '').replace(/[`"$]/g, '');
  const caB64 = Buffer.from(cfg.caCertPem || '', 'utf8').toString('base64');
  const split = cfg.fullTunnel ? '$false' : '$true';

  // EAP-MSCHAPv2 configuration XML for Add-VpnConnection -EapConfigXml.
  const eapXml = [
    '<EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig">',
    '<EapMethod><Type xmlns="http://www.microsoft.com/provisioning/EapCommon">26</Type>',
    '<VendorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorId>',
    '<VendorType xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorType>',
    '<AuthorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</AuthorId></EapMethod>',
    '<Config xmlns="http://www.microsoft.com/provisioning/EapHostConfig">',
    '<Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1">',
    '<Type>26</Type><EapType xmlns="http://www.microsoft.com/provisioning/MsChapV2ConnectionPropertiesV1">',
    '<UseWinLogonCredentials>false</UseWinLogonCredentials></EapType></Eap></Config></EapHostConfig>',
  ].join('');

  return [
    '# HomeShield NGFW - Windows IKEv2/IPSec VPN client installer',
    '# Run in an elevated PowerShell (Run as Administrator).',
    '#Requires -RunAsAdministrator',
    '$ErrorActionPreference = "Stop"',
    `$VpnName = "${name}"`,
    `$Server  = "${endpoint}"`,
    '',
    '# 1. Import the HomeShield CA into the machine Trusted Root store',
    `$caB64 = "${caB64}"`,
    '$caPath = Join-Path $env:TEMP "homeshield-ca.cer"',
    '[IO.File]::WriteAllBytes($caPath, [Convert]::FromBase64String($caB64))',
    'Import-Certificate -FilePath $caPath -CertStoreLocation Cert:\\LocalMachine\\Root | Out-Null',
    'Remove-Item $caPath -Force',
    '',
    '# 2. (Re)create the IKEv2 VPN connection with EAP-MSCHAPv2',
    'Get-VpnConnection -AllUserConnection -Name $VpnName -ErrorAction SilentlyContinue | ',
    '    Remove-VpnConnection -AllUserConnection -Force -ErrorAction SilentlyContinue',
    `[xml]$eap = '${eapXml}'`,
    'Add-VpnConnection -Name $VpnName -ServerAddress $Server -TunnelType Ikev2 `',
    '    -AuthenticationMethod Eap -EapConfigXml $eap.OuterXml -EncryptionLevel Required `',
    `    -SplitTunneling:${split} -RememberCredential -AllUserConnection -Force`,
    '',
    'Write-Host "Installed VPN connection: $VpnName -> $Server" -ForegroundColor Green',
    'Write-Host "Connect with: rasdial \\"$VpnName\\" <username> <password>  (or via Settings > VPN)"',
    '',
  ].join('\n');
}
