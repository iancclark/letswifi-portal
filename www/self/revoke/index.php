<?php declare( strict_types=1 );

/*
 * This file is part of letswifi; a system for easy eduroam device enrollment
 *
 * Copyright: Jørn Åne de Jong <jorn.dejong@letswifi.eu>
 * Copyright: Paul Dekkers, SURF <paul.dekkers@surf.nl>
 * SPDX-License-Identifier: BSD-3-Clause
 */

require \implode( \DIRECTORY_SEPARATOR, [\dirname( __DIR__, 4 ), 'src', '_autoload.php'] );

$app = new letswifi\LetsWifiApp();
$app->registerExceptionHandler();
$realm = $app->getRealm();
\assert( \array_key_exists( 'REQUEST_METHOD', $_SERVER ) ); // Psalm

$user = $app->getUserFromBrowserSession( $realm );

if ( 'POST' !== $_SERVER['REQUEST_METHOD'] ) {
	\header( 'Content-Type: text/plain', true, 405 );

	exit( "405 Method Not Allowed\r\n\r\nOnly POST is allowed for this resource\r\n" );
}

$realmManager = $app->getRealmManager();

if ( \array_key_exists( 'subject', $_POST ) && \is_string( $_POST['subject'] ) ) {
        $cert = $realmManager->getCertificate( $realm->getName(), $_POST['subject'] )

        if ( $cert['requester'] === $user ) {
	        $realmManager->revokeSubject( $realm->getName(), $_POST['subject'] );
        } else {
                \header( 'Content-Type: text/plain', true, 404 );
                exit( "404 Not found\r\n\r\nThis certificate was not found\r\n" );
        }
}

if ( $app->isBrowser() && \array_key_exists( 'returnTo', $_POST ) && \is_string( $_POST['returnTo'] ) ) {
	\header( 'Location: ' . $_POST['returnTo'] );
} else {
	\header( 'X-Result: success', false, 204 ); // No Content
}
