<?php
/**
 * Nextcloud - passman
 *
 * @copyright Copyright (c) 2016, Sander Brand (brantje@gmail.com)
 * @copyright Copyright (c) 2016, Marcos Zuriaga Miguel (wolfi@wolfi.es)
 * @license GNU AGPL version 3 or any later version
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

namespace OCA\Passman\Service;

use OCA\Passman\Activity;
use OCA\Passman\Db\Credential;
use OCA\Passman\Db\CredentialMapper;
use OCA\Passman\Db\SharingACL;
use OCA\Passman\Db\SharingACLMapper;
use OCP\AppFramework\Db\DoesNotExistException;
use OCP\AppFramework\Db\Entity;
use OCP\AppFramework\Db\MultipleObjectsReturnedException;
use OCP\IConfig;
use OCP\IURLGenerator;
use CurlHandle;
use CurlMultiHandle;


class CredentialService
{

	private $server_key;
	private $haveIBeenPwnedAPIUrl;

	public function __construct(
		private CredentialMapper $credentialMapper,
		private SharingACLMapper $sharingACL,
		private ActivityService $activityService,
		private ShareService $shareService,
		private EncryptService $encryptService,
		private CredentialRevisionService $credentialRevisionService,
		private IURLGenerator $urlGenerator,
		private VaultService $vaultService,
		private NotificationService $notificationService,
		IConfig $config,
		string $haveIBeenPwnedAPIUrl = "https://api.pwnedpasswords.com/range/"
	) {
		$this->server_key = $config->getSystemValue('passwordsalt', '');
		$this->haveIBeenPwnedAPIUrl = $haveIBeenPwnedAPIUrl;
	}

	/**
	 * Create a new credential
	 *
	 * @param array $credential
	 * @return Credential
	 * @throws \Exception
	 */
	public function createCredential(array $credential) {
		$credential = $this->encryptService->encryptCredential($credential);
		return $this->credentialMapper->create($credential);
	}

	/**
	 * Update credential
	 *
	 * @param array $credential
	 * @param false $useRawUser
	 * @return Credential|Entity
	 * @throws DoesNotExistException
	 * @throws MultipleObjectsReturnedException
	 */
	public function updateCredential(array $credential, $useRawUser = false)
	{
		$credential = $this->encryptService->encryptCredential($credential);
		return $this->credentialMapper->updateCredential($credential, $useRawUser);
	}

	/**
	 * Update credential
	 *
	 * @param Credential $credential
	 * @return Credential|Entity
	 * @throws DoesNotExistException
	 * @throws MultipleObjectsReturnedException
	 */
	public function upd(Credential $credential) {
		$credential = $this->encryptService->encryptCredential($credential);
		return $this->credentialMapper->updateCredential($credential->jsonSerialize(), false);
	}

	/**
	 * Delete credential
	 *
	 * @param Credential $credential
	 * @return Entity
	 */
	public function deleteCredential(Credential $credential) {
		$this->shareService->unshareCredential($credential->getGuid());
		return $this->credentialMapper->deleteCredential($credential);
	}

	/**
	 * Delete leftovers from a credential
	 * @param Credential $credential
	 * @throws \Exception
	 */
	public function deleteCredentialParts(Credential $credential, $userId) {
		$this->activityService->add(
			'item_destroyed_self', [$credential->getLabel()],
			'', [],
			'', $userId, Activity::TYPE_ITEM_ACTION);
		$this->shareService->unshareCredential($credential->getGuid());
		foreach ($this->credentialRevisionService->getRevisions($credential->getId()) as $revision) {
			$id = $revision['revision_id'];
			if (isset($id)) {
				$this->credentialRevisionService->deleteRevision($id, $userId);
			}
		}
		$this->notificationService->deleteNotificationsOfCredential($credential);
	}

	/**
	 * Get credentials by vault id
	 *
	 * @param int $vault_id
	 * @param string $user_id
	 * @return Entity[]
	 * @throws \Exception
	 */
	public function getCredentialsByVaultId(int $vault_id, string $user_id) {
		$credentials = $this->credentialMapper->getCredentialsByVaultId($vault_id, $user_id);
		foreach ($credentials as $index => $credential) {
			$credentials[$index] = $this->encryptService->decryptCredential($credential);
		}
		return $credentials;
	}

	/**
	 * Get a random credential from given vault
	 *
	 * @param int $vault_id
	 * @param string $user_id
	 * @return mixed
	 */
	public function getRandomCredentialByVaultId(int $vault_id, string $user_id) {
		$credentials = $this->credentialMapper->getRandomCredentialByVaultId($vault_id, $user_id);
		foreach ($credentials as $index => $credential) {
			$credentials[$index] = $this->encryptService->decryptCredential($credential);
		}
		return array_pop($credentials);
	}

	/**
	 * Get expired credentials.
	 *
	 * @param int $timestamp
	 * @return Entity[]
	 * @throws \Exception
	 */
	public function getExpiredCredentials(int $timestamp) {
		$credentials = $this->credentialMapper->getExpiredCredentials($timestamp);
		foreach ($credentials as $index => $credential) {
			$credentials[$index] = $this->encryptService->decryptCredential($credential);
		}
		return $credentials;
	}

	/**
	 * Get a single credential.
	 *
	 * @param int $credential_id
	 * @param string $user_id
	 * @return array|Credential
	 * @throws DoesNotExistException
	 * @throws MultipleObjectsReturnedException
	 */
	public function getCredentialById(int $credential_id, ?string $user_id) {
		$credential = $this->credentialMapper->getCredentialById($credential_id);
		if ($credential->getUserId() === $user_id) {
			return $this->encryptService->decryptCredential($credential);
		} else {
			$acl = $this->sharingACL->getItemACL($user_id, $credential->getGuid());
			if ($acl->hasPermission(SharingACL::READ)) {
				return $this->encryptService->decryptCredential($credential);
			} else {
				throw new DoesNotExistException("Did expect one result but found none when executing");
			}
		}
	}

	/**
	 * Check if a credential exists by id.
	 *
	 * @param int $credential_id
	 * @return bool
	 * @throws DoesNotExistException
	 * @throws MultipleObjectsReturnedException
	 */
	public function credentialExistsById(int $credential_id): bool {
		return $this->credentialMapper->getCredentialById($credential_id) !== null;
	}

	/**
	 * Get credential label by credential id.
	 *
	 * @param int $credential_id
	 * @return array|Credential
	 * @throws DoesNotExistException
	 * @throws MultipleObjectsReturnedException
	 */
	public function getCredentialLabelById(int $credential_id) {
		$credential = $this->credentialMapper->getCredentialLabelById($credential_id);
		return $this->encryptService->decryptCredential($credential);
	}

	/**
	 * Get credential by guid
	 *
	 * @param string $credential_guid
	 * @param string|null $user_id
	 * @return array|Credential
	 * @throws DoesNotExistException
	 * @throws MultipleObjectsReturnedException
	 */
	public function getCredentialByGUID(string $credential_guid, string $user_id = null) {
		$credential = $this->credentialMapper->getCredentialByGUID($credential_guid, $user_id);
		return $this->encryptService->decryptCredential($credential);
	}

	public function getDirectEditLink(Credential $credential): string {
		$vaults = $this->vaultService->getById($credential->getVaultId(), $credential->getUserId());
		return $this->urlGenerator->getAbsoluteURL(
			$this->urlGenerator->linkTo(
				'',
				'index.php/apps/passman/#/vault/' . $vaults[0]->getGuid() . '/edit/' . $credential->getGuid()
			)
		);
	}

	private function preparePwnedPasswordUrl(string $fiveAnonymitySha1Password): string {
		return "{$this->haveIBeenPwnedAPIUrl}/{ltrim($fiveAnonymitySha1Password)}";
	}

	private function prepareCurl(string $fiveAnonymitySha1Password, bool $padding = true) {
		$url = $this->preparePwnedPasswordUrl($fiveAnonymitySha1Password);
		$curl = curl_init($url);
		$headers = [
			"Add-Padding: {$padding}"
		];

		curl_setopt_array($curl, [
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_HTTPHEADER => $headers
		]);

		return $curl;

	}

	private function execCurl(CurlHandle $curl): string {
		$response = curl_exec($curl);
		curl_close($curl);
		return $response;
	}

	private function fiveAnonymitySha1Password(string $sha1Password): string {
		return substr($sha1Password, 0, 5);
	}

	private function prepareMultiCurl(array $sha1Prefixes, CurlMultiHandle $curlMultiHandle) {
		$curlHandles = [];

		foreach ($sha1Prefixes as $i => $sha1Prefix) {
			$curlHandle = $this->prepareCurl($sha1Prefix);
			curl_multi_add_handle($curlMultiHandle, $curlHandle);
			$curlHandles[$i] = $curlHandle;
		}
		return $curlHandles;
	}

	private function checkCurlResponse(string $response, string $fiveAnonymitySha1Password, string $sha1Suffix): bool {
		$lines = preg_split('/\r\n|\r|\n/', trim($response), -1, PREG_SPLIT_NO_EMPTY);


		return array_any($lines, function ($line) use ($fiveAnonymitySha1Password, $sha1Suffix) {
			[$pwnedSha1Suffix, $pwnedCount] = explode(':', $line, 2);
			return (int) $pwnedCount > 0 && hash_equals($sha1Suffix, $pwnedSha1Suffix);
		});
	}

	private function execMultiCurl(CurlMultiHandle $curlMultiHandle, array $curlHandles, ?callable $completionCallback = null): array {
		$full_curl_multi_exec = function ($mh, &$still_running) {
			do {
				$rv = curl_multi_exec($mh, $still_running);
			} while ($rv === CURLM_CALL_MULTI_PERFORM);
			return $rv;
		};

		$still_running = null;
		$full_curl_multi_exec($curlMultiHandle, $still_running);
		$responses = [];
		do {
			curl_multi_select($curlMultiHandle);
			$full_curl_multi_exec($curlMultiHandle, $still_running);

			while ($info = curl_multi_info_read($curlMultiHandle)) {
				$ch = $info["handle"];
				$index = array_search($ch, $curlHandles, true);

				if ($completionCallback) {
					$response = curl_multi_getcontent($ch);
					$completionCallback($index, $response);
				}

				$responses[$index] = curl_multi_getcontent($ch);

				curl_multi_remove_handle($curlMultiHandle, $ch);
				curl_close($ch);
			}
		} while ($still_running);

		curl_multi_close($curlMultiHandle);

		return $responses;
	}

	private function splitSha1Password(string $sha1Password) {
		return [$this->fiveAnonymitySha1Password($sha1Password), substr($sha1Password, 6)];
	}

	public function hasCredentialBeenPwned(int $credentialId, int $user_id)
	{
		$credential = $this->getCredentialById($credentialId, $user_id);
		$sha1Password = sha1($credential->getPassword());
		unset($credential);
		list($fiveAnonymitySha1Password, $sha1Suffix) = $this->splitSha1Password($sha1Password);

		$ch = $this->prepareCurl($fiveAnonymitySha1Password);
		$response = $this->execCurl($ch);
		return $this->checkCurlResponse($response, $fiveAnonymitySha1Password, $sha1Suffix);
	}

	public function whichVaultCredentialsHaveBeenPwned(int $vault_id, int $user_id) {
		$credentials = $this->getCredentialsByVaultId($vault_id, $user_id);

		$sha1Passwords = array_map(function ($credential) {
			$sha1Password = $credential->getPassword();
			return $this->splitSha1Password($sha1Password);
		}, $credentials);

		$credential_ids = array_map(function ($credential) {
			return $credential->getId();
		}, $credentials);

		unset($credentials);

		$curlMultiHandle = curl_multi_init();
		$curlHandles = $this->prepareMultiCurl(array_column($sha1Passwords, 0), $curlMultiHandle);

		$responses = $this->execMultiCurl($curlMultiHandle, $curlHandles);

		$compromisedCredentialIds = [];
		foreach ($responses as $i => $response) {
			list($sha1Prefix, $sha1Suffix) = $sha1Passwords[$i];
			$compromised = $this->checkCurlResponse($response, $sha1Prefix, $sha1Suffix);
			if ($compromised) {
				$compromisedCredentialIds[] = $credential_ids[$i];
			}
		}
		return $compromisedCredentialIds;
	}

	public function hasCredentialBeenPwnedByGUID(int $guid, int $user_id = null) {
		$credential = $this->getCredentialByGUID($guid, $user_id);
		$sha1Password = sha1($credential->getPassword());
		unset($credential);
		list($sha1Prefix, $sha1Suffix) = $this->splitSha1Password($sha1Password);

		$ch = $this->prepareCurl($sha1Prefix);
		$response = $this->execCurl($ch);
		return $this->checkCurlResponse($response, $sha1Prefix, $sha1Suffix);

	}

}
