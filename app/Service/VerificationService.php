<?php

namespace App\Service;

use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
use Illuminate\Foundation\Bus\DispatchesJobs;
use Illuminate\Foundation\Validation\ValidatesRequests;
use GuzzleHttp\Client;
use App\Models\verification_result;

class VerificationService
{
    public function parseData(string $data) : array
    {
        $resultArray = [];
        $dataJsonArray = json_decode($data, true);

        if($dataJsonArray == null)
            $dataJsonArray = [];
        
        return $dataJsonArray;
    }

   public function verify(array $dataJsonArray):string
   {
        $resultArray = [];
        $code = 'invalid_signature';
        $dataId = '';

        if($dataJsonArray != null)
        {
            $arrayToProcessed = [];
            $signature = null;

            if(array_key_exists('data', $dataJsonArray))
                $arrayToProcessed[''] = $dataJsonArray['data'];

            while(sizeof($arrayToProcessed) > 0)
            {
                foreach($arrayToProcessed as $elementKey => $element)
                {
                     foreach($element as $key => $val)
                     {
                        if(is_array($val))
                            $arrayToProcessed[$key] = $val;
                        else
                        {
                            $combinedKey = $key;

                            if(strlen($elementKey) > 0)
                                $combinedKey = $elementKey.'.'.$key;

                            $resultArray[$combinedKey] = 
                                    hash('sha256','{"'.$combinedKey.'":'.'"'.$val.'"'.'}');
                        }
                     }

                     unset($arrayToProcessed[$elementKey]);
                }
            }

            $code = $this->fieldsValidator($resultArray);

            if(strtolower($code) == "valid")
            {
                //Validate issuer by guzzling 
                $issuerKey = null;

                if(array_key_exists('issuer', $dataJsonArray['data']))
                {
                    if(array_key_exists('identityProof', $dataJsonArray['data']['issuer']))
                    {
                        if(array_key_exists('key', $dataJsonArray['data']['issuer']['identityProof']))
                            $issuerKey = $dataJsonArray['data']['issuer']['identityProof']['key'];
                    }
                }

                $repositoryData = $this->getDataFromRepository("https://dns.google/resolve?name=ropstore.accredify.io&type=TXT");

                $code = $this->verifyIssuer($issuerKey, $repositoryData);

                if(strtolower($code) == "valid")
                {
                    //generate signature using array of hashes sort them and turn them into json format
                    //eg.["018f2ca93ea216be4211d751417cef906083b027bbe101c43c1f934a90be1c61","6d5aefd2484b566350e5aee4302151d834f120cc267219ce4beec7eee1f6e691","88e287c3b0e2fcaeac173b7a20e3357342ad75cb2ceb849b3f7176c4026379b2","8d79f393cc294fd3daca0402209997db5ff8a2ad1a498702f0956952677881ae","a8aa49c6d150fab1fd77213f1f182c42ece261b30822b0c1c12826ef4599238b","b38da593123c5295845996b08502a115c2ed5e1f42745ed45fba2a0b4ea3ed47","c6cd7ca418ee8286d115d10ab30b47b8758d8aa4ef0837ef83f46b1c6e47084e","cd77eab0fa4b92136f883dfe6fe63d7ee68a98a7697874609a5f9d24adaa0f04","d94a0e7c2e7f61c7b29fede334c1b501a8b7cc8d46876273e92c4412ad82f575"]

                    $hashArray = array_values($resultArray);
                    sort($hashArray);

                    //turn the sorted array into json and generate a sha256 hash
                    $computedSignature =  hash('sha256',json_encode($hashArray));

                    //verify the signature against the input
                    $validSignatureFlag = $this->verifySignature($dataJsonArray, $computedSignature);

                    if($validSignatureFlag == true)
                        $code = "verified";
                }
            }

            //Save to database
            $dataId = $this->getIdFromData($dataJsonArray);

            verification_result::create(
                    ['user_id' => $dataId, 'file_type' => 'JSON', 'verification_result' => $code]
            );
        }

        return $code;
   }


   public function getIdFromData(array $dataJsonArray) : ?string
   {
        $dataId = null;
        if(array_key_exists('data', $dataJsonArray))
        {
            if(array_key_exists('id', $dataJsonArray['data']))
            {
                $dataId = $dataJsonArray['data']['id'];
            }
        }

        return $dataId;
   }

   public function getIssuerName(array $dataJsonArray) : string 
   {
        $issuerName = "";
        if(array_key_exists('data', $dataJsonArray))
        {
            if(array_key_exists('issuer', $dataJsonArray['data']))
            {
                 if(array_key_exists('name', $dataJsonArray['data']['issuer']))
                 {
                    $issuerName = $dataJsonArray['data']['issuer']['name'];
                 }
            }
        }

        return $issuerName;
   }

   public function verifySignature(array $dataJson, string $computedSignature) : bool
   {
        $signature = null;
        $flag = false;

        if(array_key_exists('signature', $dataJson))
        {
            if(array_key_exists('targetHash', $dataJson['signature']))
                $signature = $dataJson['signature']['targetHash'];
        }

        if($signature != null)
        {
            if($signature == $computedSignature)
                $flag = true;

        }   

        return $flag;
   }

   public function hashingArray(array $hashArray) : string
   {
        return hash('sha256',json_encode($hashArray));
   }


   public function getDataFromRepository(string $url) : array
   {
        $result_json_array = [];

        try
        {
            $client = new Client();
            $response = $client->request('GET', $url, ['verify' => false]);

            $result = $response->getBody()->getContents();
            $result_json_array = json_decode($result, true);

        }
        catch(\GuzzleHttp\Exception\ClientException $e)
        {
            $result_json_array = [];
        }

        return $result_json_array;
   }

   public function verifyIssuer(string $issuerData, array $result_json_array) : string
   {
        $code = "invalid_issuer";
        $flag = false;

        if($issuerData != null)
        {
            if(sizeof($result_json_array) > 0)
            {
                if(array_key_exists('Answer', $result_json_array))
                {
                    $result_json_array = $result_json_array['Answer'];

                    foreach($result_json_array as $element)
                    {
                        if(array_key_exists('data',$element))
                        {
                            if(str_contains($element['data'], $issuerData))
                            {
                                $flag = true;
                                break;
                            }
                        }
                    }
                   
                }
              
            }

        }

      
        if($flag == true)
            $code = "valid";

        return $code;

   }

   public function fieldsValidator(array $resultArray) : string
   {
        $code = "valid";

        if(!array_key_exists('recipient.name', $resultArray) || 
            !array_key_exists('recipient.email', $resultArray))
                 $code = "invalid_recipient";

        if(!array_key_exists('issuer.name', $resultArray) || 
                !array_key_exists('identityProof.type', $resultArray) || 
                !array_key_exists('identityProof.key', $resultArray) ||
                !array_key_exists('identityProof.location', $resultArray))
        {
            $code = "invalid_issuer";
        }

        return $code;
   }
}
