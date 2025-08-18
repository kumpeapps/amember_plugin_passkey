<?php
require_once __DIR__ . '/../../../vendor/autoload.php';

use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\RelyingParty;
use Webauthn\Server;

// Helper functions for WebAuthn registration and authentication

function beginRegistration($user) {
	// $user should be an array/object with id, name, displayName
	$rp = new RelyingParty(
		'aMember', // Name
		$_SERVER['HTTP_HOST'], // ID
		null // icon
	);
	$server = new Server($rp, new PasskeyCredentialSourceRepository());
	$userEntity = new \Webauthn\PublicKeyCredentialUserEntity(
		$user['name'],
		$user['id'],
		$user['displayName']
	);
	$options = $server->generatePublicKeyCredentialCreationOptions($userEntity);
	$_SESSION['webauthn_registration'] = serialize($options);
	return json_encode($options);
}


function finishRegistration($user, $clientData) {
	$rp = new RelyingParty('aMember', $_SERVER['HTTP_HOST'], null);
	$server = new Server($rp, new PasskeyCredentialSourceRepository());
	$options = unserialize($_SESSION['webauthn_registration']);
	$publicKeyCredential = \Webauthn\PublicKeyCredentialLoader::loadArray($clientData);
	$response = $publicKeyCredential->getResponse();
	if (!$response instanceof AuthenticatorAttestationResponse) {
		throw new \Exception('Invalid response type');
	}
	$credentialSource = $server->processAttestationResponse($publicKeyCredential, $options, $_SERVER['HTTP_HOST']);
	// Store $credentialSource in DB for $user
	// ...
	return true;
}


function beginAuthentication($user) {
	$rp = new RelyingParty('aMember', $_SERVER['HTTP_HOST'], null);
	$server = new Server($rp, new PasskeyCredentialSourceRepository());
	// Fetch credentials for user from DB
	$credentials = []; // TODO: fetch from DB
	$options = $server->generatePublicKeyCredentialRequestOptions($credentials);
	$_SESSION['webauthn_authentication'] = serialize($options);
	return json_encode($options);
}


function finishAuthentication($user, $clientData) {
	$rp = new RelyingParty('aMember', $_SERVER['HTTP_HOST'], null);
	$server = new Server($rp, new PasskeyCredentialSourceRepository());
	$options = unserialize($_SESSION['webauthn_authentication']);
	$publicKeyCredential = \Webauthn\PublicKeyCredentialLoader::loadArray($clientData);
	$response = $publicKeyCredential->getResponse();
	if (!$response instanceof AuthenticatorAssertionResponse) {
		throw new \Exception('Invalid response type');
	}
	$credentialSource = $server->processAssertionResponse($publicKeyCredential, $options, $user['id']);
	// Validate and update sign count in DB
	// ...
	return true;
}

// Dummy repository for now
class PasskeyCredentialSourceRepository implements PublicKeyCredentialSourceRepository {
	public function findOneByCredentialId(string $credentialId): ?PublicKeyCredentialSource {
		// TODO: fetch from DB
		return null;
	}
	public function saveCredentialSource(PublicKeyCredentialSource $publicKeyCredentialSource): void {
		// TODO: save to DB
	}
	public function findAllForUserEntity(\Webauthn\PublicKeyCredentialUserEntity $userEntity): array {
		// TODO: fetch all for user
		return [];
	}
}
