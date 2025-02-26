<?php declare( strict_types=1 );

/*
 * This file is part of letswifi; a system for easy eduroam device enrollment
 *
 * Copyright: Jørn Åne de Jong <jorn.dejong@letswifi.eu>
 * Copyright: Paul Dekkers, SURF <paul.dekkers@surf.nl>
 * SPDX-License-Identifier: BSD-3-Clause
 */

namespace letswifi\profile\network;

class WiredNetwork implements Network
{
	/** @var string */
	private $name;

	public function __construct( string $name )
	{
		$this->name = $name;
	}

	public function getName()
	{
		return $this->name;
	}
}
