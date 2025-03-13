<?php declare( strict_types=1 );

/*
 * This file is part of letswifi; a system for easy eduroam device enrollment
 *
 * Copyright: Jørn Åne de Jong <jorn.dejong@letswifi.eu>
 * Copyright: Paul Dekkers, SURF <paul.dekkers@surf.nl>
 * SPDX-License-Identifier: BSD-3-Clause
 */

require \implode( \DIRECTORY_SEPARATOR, [\dirname( __DIR__, 2 ), 'src', '_autoload.php'] );
$basePath = '../../..';

$app = new letswifi\LetsWifiApp();
$app->registerExceptionHandler();

$realmManager = $app->getRealmManager();
$realm = $app->getRealm();
$user = $app->getUserFromBrowserSession( $realm );

if ( $user ) {
	$certificates = $realmManager->listUserCertificates( $realm->getName(), $user->getUserId() );
	$queryVars = ['user' => $user->getUserId() ];
} else {
	\assert( false, 'No user, this should not be possible' );

	exit;
}

$app->render( [
	'href' => "{$basePath}/admin/user/get/?" . \http_build_query( $queryVars ),
	'jq' => '.certificates | map(del(.csr,.x509))',
	// TSV seems like fun, but it looks like empty columns disappear
	// 'jq' => '.certificates[] | [.serial, .requester, .sub, .issued, .expires, .revoked, .usage, .client] | @tsv',
	'certificates' => $certificates,
	'user' => ['name' => $user->getUserId() ],
	'form' => [
		'realm' => $realm->getName(),
                // TODO: need a user specific revoke 
		'action' => 'revoke/',
	],
], 'self-user-get', $basePath );
