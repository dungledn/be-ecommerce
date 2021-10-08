<?php

namespace App\Http\Controllers\Api;

use App\Models\User;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required',
            'email' => 'required|email|unique:users,email',
            'password' => 'required|min:8'
        ]);
        if ($validator->fails()) {
            return response()->json([
                'validation_errors' => $validator->messages()
            ]);
        }

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password)
        ]);

        $token = $user->createToken($user->email . '_token')->plainTextToken;

        return response()->json([
            'status' => Response::HTTP_OK,
            'name' => $user->name,
            'token' => $token,
            'message' => 'Registered Successfully'
        ]);
    }

    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required',
            'password' => 'required'
        ]);

        if ($validator->fails()) {
            return response()->json([
                'validation_errors' => $validator->messages()
            ]);
        }

        $user = User::where('email', $request->email)->first();
        
        if (!$user || !Hash::check($request->password, $user->password)) {
            return response()->json([
                'status' => Response::HTTP_UNAUTHORIZED,
                'message' => 'Invalid Credentials'
            ]);
        } else {
            if ($user->role_as == User::Admin) {
                $token = $user->createToken($user->email. '_token', ['server:admin'])->plainTextToken;
            } else {
                $token = $user->createToken($user->email . '_token', [''])->plainTextToken;
            }
        }
        
        return response()->json([
            'status' => Response::HTTP_OK,
            'name' => $user->name,
            'token' => $token,
            'message' => 'Logged In Successfully',
            'role' => $user->role_as
        ]);
    }

    public function logout()
    {
        auth()->user()->tokens()->delete();

        return response()->json([
            'status' => Response::HTTP_OK,
            'message' => 'Logged Out Successfully'
        ]);
    }
}
