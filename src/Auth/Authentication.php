<?php
/**
 * Copyright (C) 1997-2020 Reyesoft <info@reyesoft.com>.
 *
 * This file is part of php-afip-ws. php-afip-ws can not be copied and/or
 * distributed without the express permission of Reyesoft
 */

declare(strict_types=1);

namespace Multinexo\Auth;

use Multinexo\Drivers\FileSystemDriver;
use Multinexo\Drivers\LocalFileSystem;
use Multinexo\Exceptions\WsException;
use Multinexo\Models\AfipConfig;
use Multinexo\Models\AfipWebService;
use Multinexo\WSAA\Wsaa;
use SoapClient;
use stdClass;

class Authentication
{
    /** @var FileSystemDriver */
    public $fs;
    /** @var mixed */
    public $configuracion;
    /** @var array|stdClass|string */
    public $authRequest;
    /** @var SoapClient */
    public $client;

    // Authentication constructor.
    public function __construct(AfipConfig $newConf, string $ws)
    {
        $conf = AfipWebService::setConfig($newConf);
        $this->configuracion = json_decode(json_encode($conf));
        $this->configuracion->production = !$newConf->sandbox;
        $this->ws = $ws;
        $this->fs = $newConf->fs ?? new LocalFileSystem();
        $this->connectAfip();
    }

    private function connectAfip()
    {
        try {
            (new Wsaa())->checkTARenovation($this);
            $this->client = $this->getClient();
            $this->authRequest = $this->getCredentials();
            AfipWebService::checkWsStatusOrFail($this->ws, $this->client);
        } catch (WsException $exception) {
            throw $exception;
        }
    }

    private function getClient(): SoapClient
    {
        $ta = $this->configuracion->dir->xml_generados . 'TA-' . $this->configuracion->cuit
            . '-' . $this->ws . '.xml';
        $wsdl = dirname(__DIR__) . '/' . strtoupper($this->ws) . '/' . $this->ws . '.wsdl';

        if(!$this->fs->exists($ta)){
            throw new WsException('Fallo al abrir: ' . $ta);
        }

        if (!file_exists($wsdl)) {
            throw new WsException('Fallo al abrir: ' . $wsdl);
        }

        return new SoapClient(
            $wsdl,
            [
                'soap_version' => SOAP_1_2,
                'location' => $this->configuracion->url->{$this->ws},
                'exceptions' => 0,
                'trace' => 1,
                'stream_context' => stream_context_create(options: [
                    'ssl' => [
                        'verify_peer' => true,
                        'verify_peer_name' => true,
                        'allow_self_signed' => false,
                        'ciphers' => 'DEFAULT:@SECLEVEL=1'
                    ]
                ])
            ]
        );
    }

    /**
     * @return array|stdClass|string
     */
    private function getCredentials()
    {
        $ta = $this->configuracion->dir->xml_generados . 'TA-' . $this->configuracion->cuit
            . '-' . $this->ws . '.xml';
        $content = $this->fs->get($ta);
        $TA = simplexml_load_string($content);
        if ($TA === false) {
            return '';
        }
        $token = $TA->credentials->token;
        $sign = $TA->credentials->sign;
        $authRequest = '';
        if ($this->ws === 'wsmtxca') {
            $authRequest = [
                'token' => $token,
                'sign' => $sign,
                'cuitRepresentada' => $this->configuracion->cuit,
            ];
        } elseif ($this->ws === 'wsfe') {
            $authRequest = [
                'Token' => $token,
                'Sign' => $sign,
                'Cuit' => $this->configuracion->cuit,
            ];
        } elseif ($this->ws === 'wspn3') {
            $authRequest = new stdClass();
            $authRequest->token = (string) $token;
            $authRequest->sign = (string) $sign;
        }

        return $authRequest;
    }
}
