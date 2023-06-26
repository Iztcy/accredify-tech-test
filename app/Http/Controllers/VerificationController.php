<?php

namespace App\Http\Controllers;

use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
use Illuminate\Foundation\Bus\DispatchesJobs;
use Illuminate\Foundation\Validation\ValidatesRequests;
use Illuminate\Routing\Controller as BaseController;
use Illuminate\Http\Request;
use Validator;
use Response;
use App\DTO\VerificationResponseDTO; 
use App\Service\VerificationService;


class VerificationController extends BaseController
{
    use AuthorizesRequests, DispatchesJobs, ValidatesRequests;

    public function verify(Request $request)
    {
        $validator = Validator::make($request->all(), [
           'cert' => 'file|required|max:2048'
        ]);

        if($validator->fails())
            return response()->json(['message' => 'Bad request'], 400);

        $certDetails = $request->file('cert');

        if($certDetails->getClientOriginalExtension() != "oa")
            return response()->json(['message' => 'Bad request'], 400);

        $dataString = file_get_contents($certDetails);
        $verficationService = new VerificationService();
        $dataJsonArray  = $verficationService->parseData($dataString);

        $dataId = $verficationService->getIdFromData($dataJsonArray);

        if($dataId == null)
            return response()->json(['message' => 'Bad request'], 400);

        $result = $verficationService->verify($dataJsonArray);
        $issuer = $verficationService->getIssuerName($dataJsonArray);

        $verificationResponseDTO = new VerificationResponseDTO();
        $verificationResponseDTO->issuer = $issuer;
        $verificationResponseDTO->result = $result;

        return response()->json(['data' => $verificationResponseDTO], 200);
        //
    }
}
