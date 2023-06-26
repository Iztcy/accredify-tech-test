<?php

namespace Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Foundation\Testing\WithFaker;
use Tests\TestCase;
use App\Service\VerificationService;

class VerificationServiceTest extends TestCase
{
    /**
     * A basic feature test example.
     *
     * @return void
     */
    public function testParseData()
    {
        $verificationService = new VerificationService();
        $data = '{"key" : "value"}';

        $result = $verificationService->parseData($data);
        $this->assertNotNull($result);
        $this->assertGreaterThan(0, sizeof($result), true);

        $data = '{"key" : "value"..}';
        $result = $verificationService->parseData($data);
        $this->assertNotNull($result);
        $this->assertEquals(0, sizeof($result));
    }


    public function testGetIdFromData() 
    {
        $verificationService = new VerificationService();
        $testDataArrayInner['id'] = "testID";
        $testDataArray['data'] = $testDataArrayInner;
        $result = $verificationService->getIdFromData($testDataArray);

        $this->assertEquals($result,  $testDataArrayInner['id']);

        $testDataArrayInner2['sample'] = "testID";
        $testDataArray2['data'] = $testDataArrayInner2;
        $result = $verificationService->getIdFromData($testDataArray2);

        $this->assertEquals($result,  null);
   }

    public function testHashingArray() 
    {
        $hashArray = ['123456', '234567', '345678'];
        $expectedResult = hash('sha256',json_encode($hashArray));

        $verificationService = new VerificationService();
        $result = $verificationService->hashingArray($hashArray);

        $this->assertEquals($result, $expectedResult);
       
    }


    public function testGetIssuerName()
    {
        $verificationService = new VerificationService();
        $dataString = '{"data": {"id": "63c79bd9303530645d1cca00", "name": "Certificate of Completion", "recipient": {"name": "Marty McFly", "email": "marty.mcfly@gmail.com"}, "issuer": {"name": "Accredify", "identityProof": {"type": "DNS-DID", "key": "did:ethr:0x05b642ff12a4ae545357d82ba4f786f3aed84214#controller", "location": "ropstore.accredify.io"} }, "issued": "2022-12-23T00:00:00+08:00"}, "signature": {"type": "SHA3MerkleProof", "targetHash": "7a3f50f6b838bb271e93cd6713c7309bb6f0fe61e528e766430c31079ae3e6d5"} }'; 

        $dataArray = json_decode($dataString, true);
        $result = $verificationService->getIssuerName($dataArray);
        $this->assertEquals($result, $dataArray['data']['issuer']['name']);
    }



     public function testVerifySignature()
     {
        $verificationService = new VerificationService();
        $dataString = '{"data": {"id": "63c79bd9303530645d1cca00", "name": "Certificate of Completion", "recipient": {"name": "Marty McFly", "email": "marty.mcfly@gmail.com"}, "issuer": {"name": "Accredify", "identityProof": {"type": "DNS-DID", "key": "did:ethr:0x05b642ff12a4ae545357d82ba4f786f3aed84214#controller", "location": "ropstore.accredify.io"} }, "issued": "2022-12-23T00:00:00+08:00"}, "signature": {"type": "SHA3MerkleProof", "targetHash": "7a3f50f6b838bb271e93cd6713c7309bb6f0fe61e528e766430c31079ae3e6d5"} }'; 
        $dataArray = json_decode($dataString, true);
        $result = $verificationService->verifySignature($dataArray, "7a3f50f6b838bb271e93cd6713c7309bb6f0fe61e528e766430c31079ae3e6d5");
        $this->assertEquals($result, true);

        $result = $verificationService->verifySignature($dataArray, "1a3f50f6b838bb271e93cd6713c7309bb6f0fe61e528d766430c31079ae3e6d5");
        $this->assertEquals($result, false);
        
     }

     public function testVerifyIssuerData()
     {
        $verificationService = new VerificationService();

        $dataToBeVerified = "did:ethr:0x05b642ff12a4ae545357d82ba4f786f3aed84214#controller";
        $repositoryDataString = '{"Status":0,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,"Question":[{"name":"ropstore.accredify.io.","type":16}],"Answer":[{"name":"ropstore.accredify.io.","type":16,"TTL":300,"data":"openatts a=dns-did; p=did:ethr:0x05b642ff12a4ae545357d82ba4f786f3aed84214#controller; v=1.0;"},{"name":"ropstore.accredify.io.","type":16,"TTL":300,"data":"openatts a=dns-did; p=did:ethr:0x06a464971ea723177ef83df7b39dd63c373a6905#controller; v=1.0;"},{"name":"ropstore.accredify.io.","type":16,"TTL":300,"data":"openatts a=dns-did; p=did:ethr:0x2FbBdba8BF963b1648e4755f587547Bd0Ea7685a#controller; v=1.0;"},{"name":"ropstore.accredify.io.","type":16,"TTL":300,"data":"openatts a=dns-did; p=did:ethr:0x496a0f8348a092660c435cee0bb597b473ff8173#controller; v=1.0;"},{"name":"ropstore.accredify.io.","type":16,"TTL":300,"data":"openatts a=dns-did; p=did:ethr:0x757cd434dd1e93d47a4c6ed7a1b31bd88d984b45#controller; v=1.0;"},{"name":"ropstore.accredify.io.","type":16,"TTL":300,"data":"openatts a=dns-did; p=did:ethr:0x7c2f9fc979c13a3c86be64b8d2063f05ce799f6d#controller; v=1.0;"},{"name":"ropstore.accredify.io.","type":16,"TTL":300,"data":"openatts a=dns-did; p=did:ethr:0x7f7b4ad63fbfd2b1bc5bd7ec269e22a53b28f6f3#controller; v=1.0;"},{"name":"ropstore.accredify.io.","type":16,"TTL":300,"data":"openatts a=dns-did; p=did:ethr:0x8abde9e6aeeebfff9f2e24014582881a007ce74f#controller; v=1.0;"},{"name":"ropstore.accredify.io.","type":16,"TTL":300,"data":"openatts a=dns-did; p=did:ethr:0x92557d2d818fea37ee8808219e77a93aef0f5e17#controller; v=1.0;"},{"name":"ropstore.accredify.io.","type":16,"TTL":300,"data":"openatts a=dns-did; p=did:ethr:0xa979aeb39dd2307e060d7d11e1a446f358f0d21c#controller; v=1.0;"},{"name":"ropstore.accredify.io.","type":16,"TTL":300,"data":"openatts a=dns-did; p=did:ethr:0xad4dbc3ad9dc3b7f52609d5b23f3c22e3e7cefa1#controller; v=1.0;"},{"name":"ropstore.accredify.io.","type":16,"TTL":300,"data":"openatts a=dns-did; p=did:ethr:0xc04370e761f72e7d2985e274f914221efe51886e#controller; v=1.0;"},{"name":"ropstore.accredify.io.","type":16,"TTL":300,"data":"openatts a=dns-did; p=did:ethr:0xed368d1c74cdc731e119c4ca4acdf65add9af735#controller; v=1.0;"},{"name":"ropstore.accredify.io.","type":16,"TTL":300,"data":"openatts net=ethereum netId=3 addr=0x0B209E53234e5E9744d70509b74d66358df0bb27"},{"name":"ropstore.accredify.io.","type":16,"TTL":300,"data":"openatts net=ethereum netId=3 addr=0x8170f595b2b151e0e06052b79e81b80117f71181"},{"name":"ropstore.accredify.io.","type":16,"TTL":300,"data":"openatts net=ethereum netId=3 addr=0xa57a86ff03f536ccfce12ebfcd3361af421b82ed"},{"name":"ropstore.accredify.io.","type":16,"TTL":300,"data":"openatts net=ethereum netId=3 addr=0xad90a8b96fa17ae22566beb2eb5f3730771ba9ae"},{"name":"ropstore.accredify.io.","type":16,"TTL":300,"data":"openatts net=ethereum netId=3 addr=0xd604c626018d3924bfaa3b21e168451850b0fb14"}],"Comment":"Response from 2600:9000:5302:1700::1."}';

        $repositoryDataArray = json_decode($repositoryDataString, true);
        $code = $verificationService->verifyIssuer($dataToBeVerified , 
                    $repositoryDataArray);

        $this->assertEquals($code, "valid");


        $repositoryDataArray = [];
        $code = $verificationService->verifyIssuer($dataToBeVerified , 
                    $repositoryDataArray);

        $this->assertNotEquals($code, "valid");

     }
}
