<?php
namespace OCA\Passman\Service;

use CurlHandle;
use CurlMultiHandle;
use OCA\Passman\Service\CredentialService;

class HaveIBeenPwnedService
{
    private $haveIBeenPwnedAPIUrl;

    public function __construct(private CredentialService $credentialService, string $haveIBeenPwnedAPIUrl = "https://api.pwnedpasswords.com/range/")
    {
        $this->haveIBeenPwnedAPIUrl = rtrim($haveIBeenPwnedAPIUrl, "/");
    }

    private function preparePwnedPasswordUrl(string $fiveAnonymitySha1Password): string
    {
        return "{$this->haveIBeenPwnedAPIUrl}/{ltrim($fiveAnonymitySha1Password)}";
    }

    private function prepareCurl(string $fiveAnonymitySha1Password, bool $padding = true)
    {
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

    private function execCurl(CurlHandle $curl): string
    {
        $response = curl_exec($curl);
        curl_close($curl);
        return $response;
    }

    private function fiveAnonymitySha1Password(string $sha1Password): string
    {
        return substr($sha1Password, 0, 5);
    }

    private function prepareMultiCurl(array $credentials, CurlMultiHandle $curlMultiHandle)
    {
        $curlHandles = [];

        foreach ($credentials as $i => $credential) {
            $sha1Password = sha1($credential->getPassword());
            $sha1Prefix = $this->fiveAnonymitySha1Password($sha1Password);
            $curlHandle = $this->prepareCurl($sha1Prefix);
            curl_multi_add_handle($curlMultiHandle, $curlHandle);
            $curlHandles[$i] = $curlHandle;
        }
        return $curlHandles;
    }

    private function checkCurlResponse(string $response, string $fiveAnonymitySha1Password, string $sha1Password): bool
    {
        $lines = preg_split('/\r\n|\r|\n/', trim($response), -1, PREG_SPLIT_NO_EMPTY);


        return array_any($lines, function ($line) use ($fiveAnonymitySha1Password, $sha1Password) {
            [$suffixSha1, $pwnedCount] = explode(':', $line, 2);
            $completeSha1 = "{$fiveAnonymitySha1Password}{$suffixSha1}";
            return (int) $pwnedCount > 0 && hash_equals($sha1Password, $completeSha1);
        });
    }

    private function execMultiCurl(CurlMultiHandle $curlMultiHandle, array $curlHandles, ?callable $completionCallback = null): array
    {
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

    public function hasCredentialBeenPwned(int $credentialId, int $user_id)
    {
        $credential = $this->credentialService->getCredentialById($credentialId, $user_id);
        $sha1Password = sha1($credential->getPassword());
        $fiveAnonymitySha1Password = $this->fiveAnonymitySha1Password($sha1Password);

        $ch = $this->prepareCurl($fiveAnonymitySha1Password);
        $response = $this->execCurl($ch);
        return $this->checkCurlResponse($response, $fiveAnonymitySha1Password, $sha1Password);
    }

    public function whichVaultCredentialsHaveBeenPwned(int $vault_id, int $user_id)
    {
        $credentials = $this->credentialService->getCredentialsByVaultId($vault_id, $user_id);

        $curlMultiHandle = curl_multi_init();
        $curlHandles = $this->prepareMultiCurl($credentials, $curlMultiHandle);


    }
}