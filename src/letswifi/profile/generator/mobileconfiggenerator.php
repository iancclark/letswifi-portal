<?php declare( strict_types=1 );

/*
 * This file is part of letswifi; a system for easy eduroam device enrollment
 *
 * Copyright: Jørn Åne de Jong <jorn.dejong@letswifi.eu>
 * Copyright: Paul Dekkers, SURF <paul.dekkers@surf.nl>
 * SPDX-License-Identifier: BSD-3-Clause
 */

namespace letswifi\profile\generator;

use InvalidArgumentException;
use fyrkat\openssl\PKCS12;
use letswifi\LetsWifiApp;
use letswifi\profile\auth\TlsAuth;
use letswifi\profile\network\HS20Network;
use letswifi\profile\network\SSIDNetwork;
use letswifi\profile\network\IKENetwork;

class MobileConfigGenerator extends AbstractGenerator
{
	/**
	 * Generate the eap-config profile
	 */
	public function generate(): string
	{
		$uuid = static::uuidgen();
		$identifier = \implode( '.', \array_reverse( \explode( '.', $this->profileData->getRealm() ) ) );

		/** @var array<TlsAuth> */
		$caCertificates = [];
		$tlsAuthMethods = \array_filter(
			$this->authenticationMethods,
			static fn ( $a ) => $a instanceof TlsAuth && null !== $a->getPKCS12(),
		);
		if ( 1 !== \count( $tlsAuthMethods ) ) {
			throw new InvalidArgumentException( 'Expected 1 TLS auth method, got ' . \count( $tlsAuthMethods ) );
		}
		$tlsAuthMethod = \reset( $tlsAuthMethods );

		/** @psalm-suppress RedundantCondition */
		\assert( $tlsAuthMethod instanceof TlsAuth );

		$tlsAuthMethodUuid = static::uuidgen();
		$defaultPassphrase = 'pkcs12';
		if ( $pkcs12 = $tlsAuthMethod->getPKCS12() ) {
			// Remove the CA from the PKCS12 object,
			// because otherwise MacOS would trust that CA for HTTPS traffic
			$pkcs12 = new PKCS12( $pkcs12->x509, $pkcs12->privateKey );
		}
		if ( null !== $pkcs12 ) {
			// We need 3DES support, since some of our supported clients support nothing else
			$pkcs12 = $pkcs12->use3des();
		}

		/** @var array<\fyrkat\openssl\X509> */
		$caCertificates = \array_merge( $caCertificates, $tlsAuthMethod->getServerCACertificates() );
		\assert( null !== $pkcs12 );

		$result = '<?xml version="1.0" encoding="UTF-8"?>'
			. "\n" . '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
			. "\n" . '<plist version="1.0">'
			. "\n<dict>"
			. "\n	<key>PayloadDisplayName</key>"
			. "\n	<string>" . static::e( $this->profileData->getDisplayName() ) . '</string>'
			. "\n	<key>PayloadIdentifier</key>"
			. "\n	<string>" . static::e( $identifier ) . '</string>'
			. "\n	<key>PayloadUUID</key>"
			. "\n	<string>" . static::e( $uuid ) . '</string>'
			. "\n	<key>PayloadRemovalDisallowed</key>"
			. "\n	<false/>"
			. "\n	<key>PayloadType</key>"
			. "\n	<string>Configuration</string>"
			. "\n	<key>PayloadVersion</key>"
			. "\n	<integer>1</integer>"
			. "\n";
		if ( null !== $description = $this->profileData->getDescription() ) {
			$result .= '	<key>PayloadDescription</key>'
				. "\n	<string>" . static::e( $description ) . '</string>'
				. "\n";
		}
		if ( null !== $expiry = $this->getExpiry() ) {
			$result .= '	<key>RemovalDate</key>'
					. "\n	<date>" . static::e( \gmdate( 'Y-m-d\\TH:i:s\\Z', $expiry->getTimestamp() ) ) . '</date>'
					. "\n";
		}
		$result .= '	<key>PayloadContent</key>'
			. "\n	<array>"
			. "\n		<dict>"
			. "\n";
		if ( !$this->passphrase ) {
			$result .= '			<key>Password</key>'
				. "\n			<string>" . static::e( $defaultPassphrase ) . '</string>'
				. "\n";
		}
		$result .= '			<key>PayloadUUID</key>'
			. "\n			<string>" . static::e( $tlsAuthMethodUuid ) . '</string>'
			. "\n			<key>PayloadIdentifier</key>"
			. "\n			<string>" . static::e( $identifier . '.' . $tlsAuthMethodUuid ) . '</string>'
			. "\n			<key>PayloadCertificateFileName</key>"
			. "\n			<string>" . static::e( $pkcs12->x509->getSubject()->getCommonName() ) . '.p12</string>'
			. "\n			<key>PayloadDisplayName</key>"
			. "\n			<string>" . static::e( $pkcs12->x509->getSubject()->getCommonName() ) . '</string>'
			. "\n			<key>PayloadContent</key>"
			. "\n			<data>"
			. "\n				" . static::e( static::columnFormat( \base64_encode( $pkcs12->getPKCS12Bytes( $this->passphrase ?: $defaultPassphrase ) ), 52, 4 ) )
			. "\n			</data>"
			. "\n			<key>PayloadType</key>"
			. "\n			<string>com.apple.security.pkcs12</string>"
			. "\n			<key>PayloadVersion</key>"
			. "\n			<integer>1</integer>"
			. "\n		</dict>"
			. "\n";

		$uuids = \array_map(
			static fn ( $_ ) => static::uuidgen(),
			\array_fill( 0, \count( $caCertificates ), null ),
		);

		/** @var array<string,\fyrkat\openssl\X509> */
                # Try not sending a cert, avoids risk of CA disclosure to unmanaged clients
		#$caCertificates = \array_combine( $uuids, $caCertificates );
                $caCertificates = [];
		foreach ( $caCertificates as $uuid => $ca ) {
			$result .= ''
				. "\n		<dict>"
				. "\n			<key>PayloadCertificateFileName</key>"
				. "\n			<string>" . static::e( $ca->getSubject()->getCommonName() ) . '.cer</string>'
				. "\n			<key>PayloadContent</key>"
				. "\n			<data>"
				. "\n				" . static::e( static::columnFormat( \base64_encode( $ca->getX509Der() ), 52, 4 ) )
				. "\n			</data>"
				. "\n			<key>PayloadDisplayName</key>"
				. "\n			<string>" . static::e( $ca->getSubject()->getCommonName() ) . '</string>'
				. "\n			<key>PayloadIdentifier</key>"
				. "\n			<string>" . static::e( $identifier . '.' . $uuid ) . '</string>'
				. "\n			<key>PayloadType</key>"
				. "\n			<string>com.apple.security.root</string>"
				. "\n			<key>PayloadUUID</key>"
				. "\n			<string>" . static::e( $uuid ) . '</string>'
				. "\n			<key>PayloadVersion</key>"
				. "\n			<integer>1</integer>"
				. "\n		</dict>"
				. "\n";
		}
		$payloadNetworkCount = 0;
		foreach ( $this->profileData->getNetworks() as $network ) {
			if ( $network instanceof SSIDNetwork || $network instanceof HS20Network ) {
				// TODO assumes TLSAuth, it's the only option currently
				$result .= '		<dict>'
					. "\n			<key>AutoJoin</key>"
					. "\n			<true/>"
					. "\n			<key>EAPClientConfiguration</key>"
					. "\n			<dict>"
					. "\n				<key>AcceptEAPTypes</key>"
					. "\n				<array>"
					. "\n					<integer>13</integer>"
					. "\n				</array>"
					. "\n				<key>EAPFASTProvisionPAC</key>"
					. "\n				<false/>"
					. "\n				<key>EAPFASTProvisionPACAnonymously</key>"
					. "\n				<false/>"
					. "\n				<key>EAPFASTUsePAC</key>"
					. "\n				<false/>"
					. "\n				<key>PayloadCertificateAnchorUUID</key>"
					. "\n				<array>"
					. "\n";
				foreach ( $caCertificates as $uuid => $_ ) {
					$result .= '					<string>' . static::e( $uuid ) . '</string>'
						. "\n";
				}
				$result .= '				</array>'
					. "\n				<key>TLSTrustedServerNames</key>"
					. "\n				<array>"
					. "\n";
				foreach ( $tlsAuthMethod->getServerNames() as $serverName ) {
					$result .= '					<string>' . static::e( $serverName ) . '</string>'
						. "\n";
				}

				/**
				 *@psalm-suppress RedundantCondition
				 * We know $network is one of SSIDNetwork or HS20Network,
				 * but the code is clearer this way.
				 */
				if ( $network instanceof SSIDNetwork ) {
					$payloadDisplayName = static::e( $network->getSSID() );
				} elseif ( $network instanceof HS20Network ) {
					$payloadDisplayName = 'roaming via Passpoint';
				} else {
					throw new InvalidArgumentException( 'Only SSID or Hotspot 2.0 networks are supported, got ' . $network::class );
				}
				$result .= '				</array>'
					. "\n			</dict>"
					. "\n			<key>EncryptionType</key>"
					. "\n			<string>WPA</string>"
					. "\n			<key>HIDDEN_NETWORK</key>"
					. "\n			<false/>"
					. "\n			<key>PayloadCertificateUUID</key>"
					. "\n			<string>" . static::e( $tlsAuthMethodUuid ) . '</string>'
					. "\n			<key>PayloadDisplayName</key>"
					. "\n			<string>Wi-Fi (" . static::e( $payloadDisplayName ) . ')</string>'
					. "\n			<key>PayloadIdentifier</key>"
					. "\n			<string>" . static::e( $identifier ) . '.wifi.' . $payloadNetworkCount . '</string>'
					. "\n			<key>PayloadType</key>"
					. "\n			<string>com.apple.wifi.managed</string>"
					. "\n			<key>PayloadUUID</key>"
					. "\n			<string>" . static::uuidgen() . '</string>'
					. "\n			<key>PayloadVersion</key>"
					. "\n			<integer>1</integer>"
					. "\n			<key>ProxyType</key>"
					. "\n			<string>None</string>"
					. "\n";
			}
			if ( $network instanceof SSIDNetwork ) {
				$result .= '			<key>SSID_STR</key>'
					. "\n			<string>" . static::e( $network->getSSID() ) . '</string>'
					. "\n		</dict>"
					. "\n";
			} elseif ( $network instanceof HS20Network ) {
				$result .= '			<key>IsHotspot</key>'
					. "\n			<true/>"
					. "\n			<key>ServiceProviderRoamingEnabled</key>"
					. "\n			<true/>"
					. "\n			<key>DisplayedOperatorName</key>"
					. "\n			<string>" . static::e( $this->profileData->getRealm() ) . ' via Passpoint</string>'
					. "\n			<key>DomainName</key>"
					. "\n			<string>" . static::e( $this->profileData->getRealm() ) . '</string>'
					. "\n			<key>RoamingConsortiumOIs</key>"
					. "\n			<array>"
					. "\n				<string>" . \strtoupper( static::e( $network->getConsortiumOID() ) ) . '</string>'
					. "\n			</array>"
					. "\n			<key>_UsingHotspot20</key>"
					. "\n			<true/>"
					. "\n		</dict>"
					. "\n";
			} elseif( $network instanceof IKENetwork ) {
			$result .= '		<dict>'
                                . "\n" . '			<key>IKEv2</key>'
                                . "\n" . '  			<dict>'
                                . "\n" . '				<key>AuthenticationMethod</key>'
                                . "\n" . '				<string>None</string>'
                                . "\n" . '				<key>ChildSecurityAssociationParameters</key>'
                                . "\n" . '				<dict>'
                                . "\n" . '					<key>DiffieHellmanGroup</key>'
                                . "\n" . '					<integer>14</integer>'
                                . "\n" . '					<key>EncryptionAlgorithm</key>'
                                . "\n" . '					<string>AES-256</string>'
                                . "\n" . '					<key>IntegrityAlgorithm</key>'
                                . "\n" . '					<string>SHA2-256</string>'
                                . "\n" . '					<key>LifeTimeInMinutes</key>'
                                . "\n" . '					<integer>1440</integer>'
                                . "\n" . '				</dict>'
                                . "\n" . '				<key>DeadPeerDetectionRate</key>'
                                . "\n" . '				<string>Medium</string>'
                                . "\n" . '				<key>DisableMOBIKE</key>'
                                . "\n" . '				<integer>0</integer>'
                                . "\n" . '				<key>DisableRedirect</key>'
                                . "\n" . '				<integer>0</integer>'
                                . "\n" . '				<key>EnableCertificateRevocationCheck</key>'
                                . "\n" . '				<integer>0</integer>'
                                . "\n" . '				<key>EnableFallback</key>'
                                . "\n" . '				<integer>0</integer>'
                                . "\n" . '				<key>EnablePFS</key>'
                                . "\n" . '				<integer>0</integer>'
                                . "\n" . '				<key>ExtendedAuthEnabled</key>'
                                . "\n" . '				<true/>'
                                . "\n" . '				<key>IKESecurityAssociationParameters</key>'
                                . "\n" . '				<dict>'
                                . "\n" . '					<key>DiffieHellmanGroup</key>'
                                . "\n" . '					<integer>14</integer>'
                                . "\n" . '					<key>EncryptionAlgorithm</key>'
                                . "\n" . '					<string>AES-256</string>'
                                . "\n" . '					<key>IntegrityAlgorithm</key>'
                                . "\n" . '					<string>SHA2-256</string>'
                                . "\n" . '					<key>LifeTimeInMinutes</key>'
                                . "\n" . '					<integer>1440</integer>'
                                . "\n" . '				</dict>'
                                . "\n" . '				<key>LocalIdentifier</key>'
                                . "\n" . '				<string>_tls@cam.ac.uk</string>'
                                . "\n" . '				<key>PayloadCertificateUUID</key>'
				. "\n" . '      			<string>' . static::e( $tlsAuthMethodUuid ) . '</string>'
                                . "\n" . '				<key>RemoteAddress</key>'
                                . "\n" . '				<string>'. static::e( $network->getRemoteAddr()) .'</string>'
                                . "\n" . '				<key>RemoteIdentifier</key>'
                                . "\n" . '				<string>'. static::e( $network->getRemoteAddr()) .'</string>'
                                . "\n" . '				<key>ServerCertificateCommonName</key>'
                                . "\n" . '				<string>'. static::e( $network->getRemoteAddr()) .'</string>'
                                . "\n" . '				<key>UseConfigurationAttributeInternalIPSubnet</key>'
                                . "\n" . '				<integer>0</integer>'
                                . "\n" . '			</dict>'
                                . "\n" . '			<key>PayloadDescription</key>'
                                . "\n" . '			<string>Configures VPN settings</string>'
                                . "\n" . '			<key>PayloadDisplayName</key>'
                                . "\n" . '			<string>VPN</string>'
                                . "\n" . '			<key>PayloadIdentifier</key>'
				. "\n" . '			<string>' . static::e( $identifier ) . '.ike2.' . $payloadNetworkCount . '</string>'
                                . "\n" . '			<key>PayloadType</key>'
                                . "\n" . '			<string>com.apple.vpn.managed</string>'
                                . "\n" . '			<key>PayloadUUID</key>'
				. "\n" . '			<string>' . static::uuidgen() . '</string>'
                                . "\n" . '			<key>PayloadVersion</key>'
                                . "\n" . '			<integer>1</integer>'
                                . "\n" . '			<key>Proxies</key>'
                                . "\n" . '			<dict>'
                                . "\n" . '				<key>HTTPEnable</key>'
                                . "\n" . '				<integer>0</integer>'
                                . "\n" . '				<key>HTTPSEnable</key>'
                                . "\n" . '				<integer>0</integer>'
                                . "\n" . '			</dict>'
                                . "\n" . '			<key>UserDefinedName</key>'
                                . "\n" . '			<string>LetsWifi VPN Test</string>'
                                . "\n" . '			<key>VPNType</key>'
                                . "\n" . '			<string>IKEv2</string>'
                                . "\n" . '      </dict>';

			} elseif( $network instanceof WiredNetwork ) {
<<<<<<< Updated upstream
                                $result .= '<dict>'
=======
                                $result .= '<dict>' .
>>>>>>> Stashed changes
                                . "\n" .'	<key>EAPClientConfiguration</key>'
                                . "\n" .'       <dict>'
				. "\n" .'               <key>AcceptEAPTypes</key>'
				. "\n" .'               <array>'
	         		. "\n" .'                       <integer>13</integer>'
	        		. "\n" .'               </array>'
				. "\n" .'               <key>TLSTrustedServerNames</key>';
				        foreach ( $tlsAuthMethod->getServerNames() as $serverName ) {
					        $result .= '					<string>' . static::e( $serverName ) . '</string>'
						        . "\n";
				        }
<<<<<<< Updated upstream
                                $result .= '       </dict>' .
=======
			        $result .= '       </dict>'
>>>>>>> Stashed changes
			        . "\n" .'       <key>Interface</key>'
			        . "\n" .'       <string>AnyEthernet</string>'
			        . "\n" .'       <key>PayloadDisplayName</key>'
                                . "\n" .'       <string>802.1X Ethernet: Global</string>'
                                . "\n" .'       <key>PayloadIdentifier</key>'
			        . "\n" .'       <string>' / static::e( $identifier ) . '.wired.' . $payloadNetworkCount . '</string>'
<<<<<<< Updated upstream
                                . "\n" .'       <key>PayloadType</key>'
			        . "\n" .'       <string>com.apple.globalethernet.managed</string>' 
=======
                                . "\n" .'       <key>PayloadType</key>' 
			        . "\n" .'       <string>com.apple.globalethernet.managed</string>'
>>>>>>> Stashed changes
                                . "\n" .'       <key>PayloadUUID</key>'
                                . "\n" .'       <string>FB617606-203D-4B7C-90AB-2DF36BB3FEE9</string>'
                                . "\n" .'       <key>PayloadVersion</key>' 
                                . "\n" .'       <integer>1</integer>'
                                . "\n" .'       <key>SetupModes</key>'
                                . "\n" .'       <array>' 
                                . "\n" .'               <string>System</string>'
                                . "\n" .'       </array>'
                                . "\n" .'</dict>';
                        } else {
				throw new InvalidArgumentException( 'Only SSID, Hotspot 2.0, IKEv2 or wired networks are supported, got ' . $network::class );
			}
			++$payloadNetworkCount;
		}
		$result .= '	</array>'
			. "\n</dict>"
			. "\n</plist>"
			. "\n";

		$app = new LetsWifiApp();
		if ( $signer = $app->getProfileSigner() ) {
			$result = $signer->sign( $result );
		}

		return $result;
	}

	public function getFileExtension(): string
	{
		return 'mobileconfig';
	}

	public function getContentType(): string
	{
		return 'application/x-apple-aspen-config';
	}
}
