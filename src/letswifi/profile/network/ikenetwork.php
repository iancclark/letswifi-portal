<?php declare( strict_types=1 );

/*
 * This file is part of letswifi; a system for easy eduroam device enrollment
 *
 * Copyright: Jørn Åne de Jong <jorn.dejong@letswifi.eu>
 * Copyright: Paul Dekkers, SURF <paul.dekkers@surf.nl>
 * SPDX-License-Identifier: BSD-3-Clause
 */

namespace letswifi\profile\network;

class IKENetwork implements Network
{
	/** @var string */
	private $remoteaddr;
        private $name;

	public function __construct( string $remoteaddr, string $name )
	{
		$this->remoteaddr = $remoteaddr;
                $this->name = $name;
	}

	public function getRemoteAddr(): string
	{
		return $this->remoteaddr;
	}

        public function getName(): string
        {
                return $this->name;
        }
}
