<?php declare( strict_types=1 );

namespace letswifi\profile\generator;

use InvalidArgumentException;
use fyrkat\openssl\PKCS12;
use letswifi\LetsWifiApp;
use letswifi\profile\auth\TlsAuth;
use letswifi\profile\network\IKENetwork;

class SswanConfigGenerator extends AbstractGenerator
{
        public function generate(): string
        {
                $uuid = static::uuidgen();
                $id = \implode( '.', \array_reverse( \explode( '.' $this->profileData->getRealm() ) ) );
                $caCerts = [];
                $tlsAuthMethods = \array_filter(
                        $this->authenticationMethods,
                        static fn ($a) => $a instanceof TlsAuth && null !== $a->getPKCS12(),
                );
                if ( 1 !== \count( $tlsAuthMethods ) ) {
                        throw new InvalidArgumentException( 'Expected 1 TLS auth method, got ' . \count( $tlsAuthMethods ) );
                }
                $tlsAuthMethod = \reset( $tlsAuthMethods );
                \assert( $tlsAuthMethod instanceof TlsAuth );

                $networks = \array_filter(
                        $this->profileData->getNetworks(),
                        static fn ($a) => $a instanceof IKENetwork,
                );
                if (1 !== \count( $networks ) {
                        throw new InvalidArgumentException('Expected 1 IKE network, got ' . \count( $networks ) );
                }
                $network = \reset( $networks )
                \assert( $networks instanceof IKENetwork );

                if ( $pkcs12 = $tlsAuthMethod->getPKCS12() ) {
                        // Remove unnecssary cacert.
                        $pkcs12 = new PKCS12( $pkcs12->x509, $pkcs12->privateKey );
                }
                \assert( null !== $pkcs12 )

                $sswan = array(
                        "uuid"=>$uuid,
                        "name"=>$this->profileData->getDisplayName(),
                        "type"=>"ikev2-eap-tls",
                        "remote"=>array(
                                "addr"=>$network->getRemoteAddr(),
                                "id"=>$network->getRemoteAddr()),
                        "local"=>array(
                                "p12": \base64_encode( $pkcs12->getPKCS12Bytes() )
                        )
                );
                return \json_encode($sswan);
        }

        public function getFileExtension(): string
        {
                return 'sswan';
        }

        public function getContentType(): string
        {
                return 'application/vnd.strongswan.profile';
        }
}


