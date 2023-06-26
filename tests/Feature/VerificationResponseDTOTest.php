<?php

namespace Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Foundation\Testing\WithFaker;
use Tests\TestCase;
use App\DTO\VerificationResponseDTO;

class VerificationResponseDTOTest extends TestCase
{
    /**
     * A basic feature test example.
     *
     * @return void
     */
    public function testVerificationResponseDTO()
    {
        $verificationResponseDTO = new VerificationResponseDTO();
        $field_1 = "TEST";
        $field_2 = "TEST2";

        $verificationResponseDTO->issuer = $field_1;
        $verificationResponseDTO->result = $field_2;

        $this->assertEquals($field_1,  $verificationResponseDTO->issuer);
        $this->assertEquals($field_2,  $verificationResponseDTO->result);
    }
}
