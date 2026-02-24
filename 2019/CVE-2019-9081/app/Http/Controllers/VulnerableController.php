<?php


namespace App\Http\Controllers;


use Illuminate\Http\Request;

class VulnerableController extends Controller
{
    public function deserialize(Request $request) {

        $data = base64_decode($request->input('data'));

        unserialize($data);

        return "You won't see this if RCE works";
    }
}

